//! Executable, checkout-independent evidence for the accepted Python 0.1.13 migration boundary.
//!
//! The Python implementation is intentionally not shipped after the native cutover. The fixture
//! freezes the stable observations produced by the last black-box differential gate, identifies
//! the exact reviewed source tree and test bytes, and distinguishes parity requirements from
//! deliberate bug fixes. These tests execute the native binary against the frozen observations;
//! they do not make Python a runtime or build dependency.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::TempDir;

const CORPUS: &str = include_str!("fixtures/python-0.1.13-reference-contracts.json");
const NATIVE_INTEGRATION_SOURCE: &str = include_str!("native_integration_contracts.rs");

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: String,
    reference: Reference,
    equivalent_cases: Vec<Case>,
    intentional_corrections: Vec<Correction>,
}

#[derive(Debug, Deserialize)]
struct Reference {
    product: String,
    version: String,
    source_tree_git_oid: String,
    observed_gate_commit: String,
    differential_test_sha256: String,
    observed_result: String,
    supplemental_observation_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    expected: Value,
}

#[derive(Debug, Deserialize)]
struct Correction {
    id: String,
    reference_behavior: String,
    native_behavior: String,
    native_test: String,
}

struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = TempDir::new().expect("create isolated reference-contract sandbox");
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

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sync-configs"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.path().join("home"))
            .env("XDG_CONFIG_HOME", self.path().join("config"))
            .env("XDG_STATE_HOME", self.path().join("state"))
            .env("XDG_CACHE_HOME", self.path().join("cache"))
            .env("XDG_DATA_HOME", self.path().join("data"))
            .env("TMPDIR", self.path().join("tmp"))
            .env("SYNC_CONFIGS_LOG_ROOT", self.path().join("logs"))
            .env("LC_ALL", "C.UTF-8")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .current_dir(self.path());
        command
    }

    fn run(&self, manifest: &Path, extra: &[&str]) -> Output {
        self.command()
            .args([
                "--no-color",
                "--log-style",
                "off",
                "--format",
                "json",
                "--config",
            ])
            .arg(manifest)
            .args(extra)
            .output()
            .expect("execute native sync-configs")
    }
}

fn normalized_run(output: &Output) -> Value {
    if output.stdout.is_empty() {
        return json!({
            "exit_code": output.status.code(),
            "schema_version": null,
            "outcome": null,
            "dry_run": null,
            "profiles": null,
        });
    }
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected one JSON document ({error}); stdout={:?}; stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    json!({
        "exit_code": output.status.code(),
        "schema_version": value.get("schema_version"),
        "outcome": value.get("outcome"),
        "dry_run": value.get("dry_run"),
        "profiles": value.get("profiles"),
    })
}

fn observation(runs: Vec<Value>, sandbox: &Sandbox, files: &[&str], absent: &[&str]) -> Value {
    let files = files
        .iter()
        .map(|path| {
            (
                (*path).to_owned(),
                fs::read_to_string(sandbox.path().join(path)).expect("observed fixture file"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for path in absent {
        assert!(
            !sandbox.path().join(path).exists(),
            "frozen contract expected {path} to remain absent"
        );
    }
    json!({"runs": runs, "files": files, "absent": absent})
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

fn overlay_semantics(sandbox: &Sandbox) -> Value {
    let json_value: Value = serde_json::from_slice(
        &fs::read(sandbox.path().join("output/settings.json")).expect("JSON target"),
    )
    .expect("valid JSON target");
    let toml =
        fs::read_to_string(sandbox.path().join("output/settings.toml")).expect("TOML target");
    let document = toml
        .parse::<toml_edit::DocumentMut>()
        .expect("valid TOML target");
    json!({
        "json": json_value,
        "toml": {
            "user": document["user"].as_str(),
            "managed": {
                "enabled": document["managed"]["enabled"].as_bool(),
                "name": document["managed"]["name"].as_str(),
                "keep": document["managed"]["keep"].as_integer(),
            },
        },
    })
}

fn hook_fixture(sandbox: &Sandbox, fail: bool) -> PathBuf {
    sandbox.write(
        "hook.sh",
        "#!/bin/sh\nset -eu\ncase \"$1\" in\n  pre) printf 'generated\\n' > generated.txt ;;\n  post) printf 'post\\n' > post.marker ;;\n  fail) exit 23 ;;\nesac\n",
    );
    let phase = if fail { "fail" } else { "pre" };
    sandbox.manifest(&format!(
        "entries:\n  - name: hooked\n    source: ./generated.txt\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/sh hook.sh {}\n    pre_script_on_fail: abort\n    post_script: /usr/bin/sh hook.sh post\n    post_script_on_fail: abort\n",
        sandbox.path().join("output/target.txt").display(),
        phase,
    ))
}

fn execute_case(id: &str) -> Value {
    match id {
        "copy_two_pass" => {
            let sandbox = Sandbox::new();
            sandbox.write("source.txt", "desired\n");
            let manifest = sandbox.manifest(&format!(
                "default_mode: copy\nentries:\n  - name: copy-file\n    source: ./source.txt\n    target: {}\n",
                sandbox.path().join("output/target.txt").display()
            ));
            let first = normalized_run(&sandbox.run(&manifest, &[]));
            let identity = fs::metadata(sandbox.path().join("output/target.txt"))
                .and_then(|metadata| metadata.modified())
                .expect("first-pass target identity");
            let second = normalized_run(&sandbox.run(&manifest, &[]));
            assert_eq!(
                fs::metadata(sandbox.path().join("output/target.txt"))
                    .and_then(|metadata| metadata.modified())
                    .expect("second-pass target identity"),
                identity,
                "second pass rewrote the target"
            );
            observation(vec![first, second], &sandbox, &["output/target.txt"], &[])
        }
        "symlink_two_pass" => {
            let sandbox = Sandbox::new();
            sandbox.write("source.txt", "source\n");
            let manifest = sandbox.manifest(&format!(
                "entries:\n  - name: linked\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
                sandbox.path().join("output/linked.txt").display()
            ));
            let first = normalized_run(&sandbox.run(&manifest, &[]));
            let first_target = fs::read_link(sandbox.path().join("output/linked.txt"))
                .expect("first-pass symlink target");
            let second = normalized_run(&sandbox.run(&manifest, &[]));
            assert_eq!(
                fs::read_link(sandbox.path().join("output/linked.txt"))
                    .expect("second-pass symlink target"),
                first_target,
                "second pass changed the symlink target"
            );
            let relative_target = first_target
                .strip_prefix(sandbox.path())
                .expect("fixture symlink remains inside its sandbox")
                .to_string_lossy()
                .into_owned();
            json!({
                "runs": [first, second],
                "links": {"output/linked.txt": relative_target},
                "absent": [],
            })
        }
        "directory_filters_and_override" => {
            let sandbox = Sandbox::new();
            let manifest = directory_fixture(&sandbox);
            let output = normalized_run(&sandbox.run(&manifest, &[]));
            observation(
                vec![output],
                &sandbox,
                &[
                    "output/overridden.txt",
                    "output/tree/keep.txt",
                    "output/tree/nested/also.txt",
                ],
                &["output/tree/drop.tmp"],
            )
        }
        "structured_overlays_two_pass" => {
            let sandbox = Sandbox::new();
            let manifest = overlay_fixture(&sandbox);
            let first = normalized_run(&sandbox.run(&manifest, &[]));
            let first_semantics = overlay_semantics(&sandbox);
            let json_before = fs::read(sandbox.path().join("output/settings.json"))
                .expect("first-pass JSON target");
            let toml_before = fs::read(sandbox.path().join("output/settings.toml"))
                .expect("first-pass TOML target");
            let second = normalized_run(&sandbox.run(&manifest, &[]));
            assert_eq!(
                fs::read(sandbox.path().join("output/settings.json"))
                    .expect("second-pass JSON target"),
                json_before,
                "second pass rewrote the JSON target"
            );
            assert_eq!(
                fs::read(sandbox.path().join("output/settings.toml"))
                    .expect("second-pass TOML target"),
                toml_before,
                "second pass rewrote the TOML target"
            );
            assert_eq!(overlay_semantics(&sandbox), first_semantics);
            json!({"runs": [first, second], "semantics": first_semantics})
        }
        "failed_state_precondition" => {
            let sandbox = Sandbox::new();
            sandbox.write("state.json", "{\"enabled\":false}\n");
            sandbox.write("source.txt", "private-value\n");
            let manifest = sandbox.manifest(&format!(
                "state_preconditions:\n  - type: json_fields\n    path: {}\n    fields: {{enabled: true}}\n    remediation: repair caller state\nentries:\n  - name: gated\n    source: ./source.txt\n    target: {}\n    mode: copy\n",
                sandbox.path().join("state.json").display(),
                sandbox.path().join("output/target.txt").display()
            ));
            let output = sandbox.run(&manifest, &[]);
            assert!(!String::from_utf8_lossy(&output.stdout).contains("private-value"));
            observation(
                vec![normalized_run(&output)],
                &sandbox,
                &[],
                &["output/target.txt"],
            )
        }
        "hooks_success_and_abort" => {
            let success = Sandbox::new();
            let success_manifest = hook_fixture(&success, false);
            let success_output = normalized_run(&success.run(&success_manifest, &[]));
            let success_observation = observation(
                vec![success_output],
                &success,
                &["generated.txt", "output/target.txt", "post.marker"],
                &[],
            );

            let abort = Sandbox::new();
            let abort_manifest = hook_fixture(&abort, true);
            let abort_output = normalized_run(&abort.run(&abort_manifest, &[]));
            let abort_observation = observation(
                vec![abort_output],
                &abort,
                &[],
                &["generated.txt", "output/target.txt", "post.marker"],
            );
            json!({"success": success_observation, "abort": abort_observation})
        }
        "pre_hook_skip_removes_duplicate_target" => {
            let sandbox = Sandbox::new();
            sandbox.write("first.txt", "first\n");
            sandbox.write("second.txt", "second\n");
            let manifest = sandbox.manifest(&format!(
                "entries:\n  - name: skipped\n    source: ./first.txt\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/false\n    pre_script_on_fail: skip\n  - name: active\n    source: ./second.txt\n    target: {}\n    mode: copy\n",
                sandbox.path().join("output/target.txt").display(),
                sandbox.path().join("output/target.txt").display(),
            ));
            let output = normalized_run(&sandbox.run(&manifest, &[]));
            observation(vec![output], &sandbox, &["output/target.txt"], &[])
        }
        "dry_run_hooks" => {
            let sandbox = Sandbox::new();
            sandbox.write(
                "hook.sh",
                "#!/bin/sh\nset -eu\nprintf 'generated\\n' > generated.txt\nprintf 'post\\n' > post.marker\n",
            );
            let manifest = sandbox.manifest(&format!(
                "entries:\n  - name: hook\n    source: ./generated.txt\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/sh hook.sh\n    post_script: /usr/bin/sh hook.sh\n",
                sandbox.path().join("output/target.txt").display()
            ));
            let output = sandbox.run(&manifest, &["--dry-run"]);
            observation(
                vec![normalized_run(&output)],
                &sandbox,
                &[],
                &["generated.txt", "post.marker", "output/target.txt"],
            )
        }
        "profile_map_order" => {
            let sandbox = Sandbox::new();
            for (profile, contents) in [
                ("linux", "linux\n"),
                ("desktop", "desktop\n"),
                ("windows", "windows\n"),
            ] {
                sandbox.write(&format!("{profile}.txt"), contents);
            }
            let manifest = sandbox.manifest(&format!(
                "entries:\n  - name: linux\n    source: ./linux.txt\n    target: {}\n    mode: copy\n    profiles: [linux]\n  - name: desktop\n    source: ./desktop.txt\n    target: {}\n    mode: copy\n    profiles: [desktop]\n  - name: windows\n    source: ./windows.txt\n    target: {}\n    mode: copy\n    profiles: [windows]\n",
                sandbox.path().join("output/linux.txt").display(),
                sandbox.path().join("output/desktop.txt").display(),
                sandbox.path().join("output/windows.txt").display()
            ));
            let profile_map = sandbox.write(
                "profiles.yaml",
                "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
            );
            let map = profile_map.to_string_lossy();
            let output = sandbox.run(
                &manifest,
                &["--profile-map", &map, "--host-profile", "workstation"],
            );
            observation(
                vec![normalized_run(&output)],
                &sandbox,
                &["output/desktop.txt", "output/linux.txt"],
                &["output/windows.txt"],
            )
        }
        "cli_dependency_error" => {
            let sandbox = Sandbox::new();
            let profile_map = sandbox.write("profiles.yaml", "schema_version: 1\nprofiles: {}\n");
            let output = sandbox
                .command()
                .args([
                    "--profile-map",
                    profile_map.to_str().unwrap(),
                    "--log-style",
                    "off",
                ])
                .output()
                .expect("execute dependency error case");
            observation(vec![normalized_run(&output)], &sandbox, &[], &["logs"])
        }
        other => panic!("unknown frozen reference case: {other}"),
    }
}

#[test]
fn native_binary_matches_the_frozen_reference_observations() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("valid frozen reference corpus");
    assert_eq!(corpus.schema, "sync-configs-frozen-reference-v1");
    assert_eq!(corpus.reference.product, "sync-configs");
    assert_eq!(corpus.reference.version, "0.1.13");
    assert_eq!(
        corpus.reference.source_tree_git_oid,
        "598986f7bf0c1b9bdd4a66270c6c15ee3eabee90"
    );
    assert_eq!(
        corpus.reference.observed_gate_commit,
        "697d97fb20912cb63968e1cef354153b3f6a081e"
    );
    assert_eq!(
        corpus.reference.differential_test_sha256,
        "ec9bff5ba66f7d8876b98339dadcb6e2dc842a4021d3dda8506036ad3f941d03"
    );
    assert_eq!(corpus.reference.observed_result, "17 passed");
    assert_eq!(
        corpus.reference.supplemental_observation_ids,
        vec!["pre_hook_skip_removes_duplicate_target".to_owned()]
    );
    assert_eq!(corpus.equivalent_cases.len(), 10);
    for case in corpus.equivalent_cases {
        assert_eq!(execute_case(&case.id), case.expected, "case {}", case.id);
    }
}

#[test]
fn every_frozen_reference_divergence_has_an_executable_native_contract() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("valid frozen reference corpus");
    assert_eq!(corpus.intentional_corrections.len(), 7);
    for correction in corpus.intentional_corrections {
        assert!(!correction.id.is_empty());
        assert!(!correction.reference_behavior.is_empty());
        assert!(!correction.native_behavior.is_empty());
        assert!(
            NATIVE_INTEGRATION_SOURCE.contains(&format!("fn {}", correction.native_test)),
            "missing executable native contract for {}",
            correction.id
        );
    }
}
