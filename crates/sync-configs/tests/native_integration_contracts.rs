#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};
use tempfile::TempDir;

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

fn sync_configs_command(sandbox: &Sandbox) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sync-configs"));
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
    command
}

fn run(sandbox: &Sandbox, manifest: &Path, extra_arguments: &[&str]) -> Output {
    let mut command = sync_configs_command(sandbox);
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

fn run_parse_case(sandbox: &Sandbox, arguments: &[&str]) -> Output {
    sync_configs_command(sandbox)
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

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
fn copy_first_and_second_pass_are_idempotent() {
    let sandbox = Sandbox::new();
    let manifest = copy_fixture(&sandbox);

    let first = run(&sandbox, &manifest, &[]);
    assert_success(&first);
    assert_eq!(
        fs::read(sandbox.path().join("output/target.txt")).unwrap(),
        b"desired\n"
    );

    let before = ordinary_file_identity(&sandbox.path().join("output/target.txt"));
    let second = run(&sandbox, &manifest, &[]);
    assert_success(&second);
    assert_eq!(
        ordinary_file_identity(&sandbox.path().join("output/target.txt")),
        before
    );
}

#[test]
fn symlink_creation_and_second_pass_are_stable() {
    let sandbox = Sandbox::new();
    sandbox.write("source.txt", "source\n");
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: linked\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
        sandbox.path().join("output/linked.txt").display()
    ));

    let first = run(&sandbox, &manifest, &[]);
    assert_success(&first);
    let link = fs::read_link(sandbox.path().join("output/linked.txt")).unwrap();
    assert_eq!(
        link.strip_prefix(sandbox.path()).unwrap(),
        Path::new("source.txt")
    );

    let second = run(&sandbox, &manifest, &[]);
    assert_success(&second);
    assert_eq!(
        fs::read_link(sandbox.path().join("output/linked.txt")).unwrap(),
        link
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
fn directory_expansion_filters_and_source_overrides_converge() {
    let sandbox = Sandbox::new();
    let manifest = directory_fixture(&sandbox);
    let output = run(&sandbox, &manifest, &[]);
    assert_success(&output);
    assert!(!sandbox.path().join("output/tree/drop.tmp").exists());
    assert_eq!(
        fs::read_to_string(sandbox.path().join("output/overridden.txt")).unwrap(),
        "override\n"
    );
    assert_eq!(
        snapshot(&sandbox.path().join("output")),
        BTreeMap::from([
            (
                "overridden.txt".to_owned(),
                SnapshotNode::File(b"override\n".to_vec())
            ),
            ("tree".to_owned(), SnapshotNode::Directory),
            (
                "tree/keep.txt".to_owned(),
                SnapshotNode::File(b"keep\n".to_vec())
            ),
            ("tree/nested".to_owned(), SnapshotNode::Directory),
            (
                "tree/nested/also.txt".to_owned(),
                SnapshotNode::File(b"nested\n".to_vec())
            ),
        ])
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

#[test]
fn json_and_toml_overlays_converge_semantically() {
    let sandbox = Sandbox::new();
    let manifest = overlay_fixture(&sandbox);
    let first = run(&sandbox, &manifest, &[]);
    assert_success(&first);

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

    let json_before = fs::read(sandbox.path().join("output/settings.json")).unwrap();
    let toml_before = fs::read(sandbox.path().join("output/settings.toml")).unwrap();
    let second = run(&sandbox, &manifest, &[]);
    assert_success(&second);
    assert_eq!(
        fs::read(sandbox.path().join("output/settings.json")).unwrap(),
        json_before
    );
    assert_eq!(
        fs::read(sandbox.path().join("output/settings.toml")).unwrap(),
        toml_before
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
fn profile_map_selection_and_order_are_stable() {
    let sandbox = Sandbox::new();
    let (manifest, profile_map) = profile_fixture(&sandbox);
    let map_arg = profile_map.to_string_lossy().into_owned();
    let output = run(
        &sandbox,
        &manifest,
        &["--profile-map", &map_arg, "--host-profile", "workstation"],
    );
    assert_success(&output);
    assert_eq!(
        json_output(&output)["profiles"],
        json!(["linux", "desktop"])
    );
    assert!(sandbox.path().join("output/linux.txt").exists());
    assert!(sandbox.path().join("output/desktop.txt").exists());
    assert!(!sandbox.path().join("output/windows.txt").exists());
}

fn hook_fixture(sandbox: &Sandbox, fail: bool) -> PathBuf {
    sandbox.write(
        "hook.sh",
        "#!/bin/sh\nset -eu\ncase \"$1\" in\n  pre) printf 'generated\\n' > generated.txt ;;\n  post) printf 'post\\n' > post.marker ;;\n  fail) exit 23 ;;\nesac\n",
    );
    let phase = if fail { "fail" } else { "pre" };
    sandbox.manifest(&format!(
        "entries:\n  - name: hooked\n    source: ./generated.txt\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/sh hook.sh {}\n    pre_script_on_fail: abort\n    post_script: /usr/bin/sh hook.sh post\n    post_script_on_fail: abort\n",
        sandbox.path().join("output/target.txt").display(), phase,
    ))
}

#[test]
fn successful_hooks_and_aborting_pre_hook_follow_runtime_contract() {
    for fail in [false, true] {
        let sandbox = Sandbox::new();
        let manifest = hook_fixture(&sandbox, fail);
        let output = run(&sandbox, &manifest, &[]);
        if fail {
            assert_eq!(output.status.code(), Some(1));
            assert!(!sandbox.path().join("post.marker").exists());
        } else {
            assert_success(&output);
            assert!(sandbox.path().join("post.marker").exists());
            assert_eq!(
                fs::read_to_string(sandbox.path().join("output/target.txt")).unwrap(),
                "generated\n"
            );
        }
    }
}

#[test]
fn dry_run_is_read_only_end_to_end() {
    let sandbox = Sandbox::new();
    let manifest = hook_fixture(&sandbox, false);
    let output = run(&sandbox, &manifest, &["--dry-run"]);
    assert_success(&output);
    assert_eq!(json_output(&output)["dry_run"], true);
    assert!(!sandbox.path().join("generated.txt").exists());
    assert!(!sandbox.path().join("post.marker").exists());
    assert!(!sandbox.path().join("output/target.txt").exists());
}

#[test]
fn cli_dependency_errors_exit_two_without_logs() {
    let sandbox = Sandbox::new();
    let profile_map = sandbox.write("profiles.yaml", "schema_version: 1\nprofiles: {}\n");
    let output = run_parse_case(
        &sandbox,
        &[
            "--profile-map",
            profile_map.to_str().unwrap(),
            "--log-style",
            "off",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!sandbox.path().join("logs").exists());
}

#[test]
fn missing_json_field_does_not_satisfy_expected_null_end_to_end() {
    let sandbox = Sandbox::new();
    sandbox.write("state.json", "{}\n");
    sandbox.write("source.txt", "must-not-leak\n");
    let manifest = sandbox.manifest(&format!(
        "state_preconditions:\n  - type: json_fields\n    path: {}\n    fields:\n      enabled: null\n    remediation: repair state first\nentries:\n  - name: gated\n    source: ./source.txt\n    target: {}\n    mode: copy\n",
        sandbox.path().join("state.json").display(),
        sandbox.path().join("output/target.txt").display(),
    ));
    let output = run(&sandbox, &manifest, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!sandbox.path().join("output/target.txt").exists());
    assert_eq!(json_output(&output)["outcome"], "failed");
}

#[test]
fn override_manifest_hooks_execute_end_to_end() {
    let sandbox = Sandbox::new();
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

    let output = run(&sandbox, &manifest, &[]);
    assert_success(&output);
    assert_eq!(
        fs::read_to_string(sandbox.path().join("override-hooks.marker")).unwrap(),
        "pre\npost\n"
    );
}

#[test]
fn post_hooks_do_not_run_after_missing_source() {
    let sandbox = Sandbox::new();
    sandbox.write(
        "hook.sh",
        "#!/bin/sh\nset -eu\nprintf 'ran\\n' > post.marker\n",
    );
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: absent\n    source: ./missing.txt\n    target: {}\n    mode: copy\n    post_script: /usr/bin/sh hook.sh\n",
        sandbox.path().join("output/target.txt").display()
    ));
    let output = run(&sandbox, &manifest, &[]);
    assert_success(&output);
    assert!(!sandbox.path().join("post.marker").exists());
}

#[test]
fn commented_target_policy_activate_applies_end_to_end() {
    let sandbox = Sandbox::new();
    sandbox.write("desired.toml", "feature = true\n");
    sandbox.write(
        "output/settings.toml",
        "# feature = false\nuser = \"stay\"\n",
    );
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: policy\n    source: ./desired.toml\n    target: {}\n    mode: toml_overlay\n    commented_target_policy: activate\n",
        sandbox.path().join("output/settings.toml").display()
    ));
    let output = run(&sandbox, &manifest, &[]);
    assert_success(&output);
    let target = fs::read_to_string(sandbox.path().join("output/settings.toml")).unwrap();
    assert!(target.lines().any(|line| line.trim() == "feature = true"));
    assert!(target.contains("user = \"stay\""));
}

#[test]
fn unknown_manifest_fields_fail_closed_end_to_end() {
    let sandbox = Sandbox::new();
    sandbox.write("source.txt", "source\n");
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: unknown\n    source: ./source.txt\n    target: {}\n    mode: copy\n    invented_semantics: true\n",
        sandbox.path().join("output/target.txt").display()
    ));
    let output = run(&sandbox, &manifest, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!sandbox.path().join("output/target.txt").exists());
    let value = json_output(&output);
    assert_eq!(value["outcome"], "failed");
    assert_eq!(value["error_kind"], "convergence_failed");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("source\n"));
}

#[test]
fn directory_copy_detects_content_drift_end_to_end() {
    let sandbox = Sandbox::new();
    sandbox.write("source/nested.txt", "one\n");
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: directory-copy\n    source: ./source\n    target: {}\n    mode: copy\n    directory_strategy: as_directory\n    reconcile_existing: true\n",
        sandbox.path().join("output/copied").display()
    ));

    let first = run(&sandbox, &manifest, &[]);
    assert_success(&first);
    sandbox.write("source/nested.txt", "two\n");
    let second = run(&sandbox, &manifest, &[]);
    assert_success(&second);
    assert_eq!(
        fs::read_to_string(sandbox.path().join("output/copied/nested.txt")).unwrap(),
        "two\n"
    );
}

#[test]
fn strict_policy_never_adopts_an_identical_regular_file_as_symlink() {
    let sandbox = Sandbox::new();
    sandbox.write("source.txt", "same\n");
    sandbox.write("output/target.txt", "same\n");
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: strict\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
        sandbox.path().join("output/target.txt").display()
    ));
    let output = run(&sandbox, &manifest, &["--managed-path-policy", "strict"]);
    assert_success(&output);
    assert!(
        fs::symlink_metadata(sandbox.path().join("output/target.txt"))
            .unwrap()
            .is_file()
    );
}
