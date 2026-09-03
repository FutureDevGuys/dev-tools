#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use sync_configs::reconciler::{
    resolve_executable, ReconcilerPrivilege, ReconcilerRunner, ReconcilerSpec,
};
use tempfile::TempDir;

fn fake_reconciler(root: &Path, unsafe_plan: bool) -> (std::path::PathBuf, std::path::PathBuf) {
    let executable = root.join("fake-reconciler");
    let argv_log = root.join("argv.jsonl");
    let script = format!(
        r#"#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import sys

root = pathlib.Path({root:?})
with (root / "argv.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")

def result(changed=False, verified=False):
    print(json.dumps({{
        "schema": "dev-tools-reconcile-result-v1",
        "changed": changed,
        "verified": verified,
        "deferred": False,
        "input_required": [],
        "next_action": "none" if verified else "apply",
        "diagnostics": [],
    }}, sort_keys=True))

operation = sys.argv[2]
if operation == "plan":
    output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    output.write_text("plan", encoding="utf-8")
    output.chmod({mode})
    result()
elif operation == "apply":
    plan = pathlib.Path(sys.argv[sys.argv.index("--plan") + 1])
    expected = sys.argv[sys.argv.index("--sha256") + 1]
    assert hashlib.sha256(plan.read_bytes()).hexdigest() == expected
    (root / "applied").write_text("yes", encoding="utf-8")
    result(changed=True, verified=True)
elif operation == "verify":
    result(verified=True)
else:
    raise SystemExit(64)
"#,
        root = root.display().to_string(),
        mode = if unsafe_plan { "0o644" } else { "0o600" },
    );
    fs::write(&executable, script).expect("write reconciler");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("make executable");
    (executable, argv_log)
}

fn runner() -> ReconcilerRunner {
    let mut environment = BTreeMap::new();
    environment.insert("PATH".into(), "/usr/bin:/bin".into());
    ReconcilerRunner {
        environment,
        sudo_path: None,
        timeout: Duration::from_secs(5),
        output_limit: 1 << 20,
    }
}

#[test]
fn stable_alias_is_resolved_before_protocol_execution() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().expect("temp root");
    let (executable, _) = fake_reconciler(root.path(), false);
    let alias = root.path().join("owner-tool");
    symlink(&executable, &alias).expect("stable alias");

    let resolved = resolve_executable(&alias).expect("resolve alias");
    assert_eq!(
        resolved,
        executable.canonicalize().expect("canonical executable")
    );
    assert!(!resolved.is_symlink());
}

#[test]
fn exact_plan_apply_verify_grammar_and_digest_are_enforced() {
    let root = TempDir::new().expect("temp root");
    let source = root.path().join("desired.toml");
    fs::write(&source, "desired = true\n").expect("write source");
    let (executable, argv_log) = fake_reconciler(root.path(), false);
    let spec = ReconcilerSpec {
        name: "owner-tool".into(),
        executable,
        source: source.clone(),
        privilege: ReconcilerPrivilege::User,
        protocol: "dev-tools-reconcile-v1".into(),
    };

    let result = runner().run(&spec, false).expect("converge");
    assert!(result.changed);
    assert!(result.verified);
    assert!(root.path().join("applied").is_file());

    let calls: Vec<Vec<String>> = fs::read_to_string(argv_log)
        .expect("argv log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("argv JSON"))
        .collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0],
        vec![
            "reconcile",
            "plan",
            "--source",
            source.to_str().expect("utf8 source"),
            "--output",
            calls[0][5].as_str(),
            "--format",
            "json",
        ]
    );
    assert_eq!(&calls[1][..2], ["reconcile", "apply"]);
    assert_eq!(&calls[1][2..4], ["--plan", calls[0][5].as_str()]);
    assert_eq!(calls[1][4], "--sha256");
    assert_eq!(calls[1][6..], ["--format", "json"]);
    assert_eq!(
        calls[2],
        vec![
            "reconcile",
            "verify",
            "--source",
            source.to_str().expect("utf8 source"),
            "--format",
            "json",
        ]
    );
}

#[test]
fn dry_run_plans_only_and_never_applies() {
    let root = TempDir::new().expect("temp root");
    let source = root.path().join("desired.toml");
    fs::write(&source, "desired = true\n").expect("write source");
    let (executable, argv_log) = fake_reconciler(root.path(), false);
    let spec = ReconcilerSpec {
        name: "owner-tool".into(),
        executable,
        source,
        privilege: ReconcilerPrivilege::User,
        protocol: "dev-tools-reconcile-v1".into(),
    };

    let result = runner().run(&spec, true).expect("dry run");
    assert!(!result.changed);
    assert!(!root.path().join("applied").exists());
    assert_eq!(fs::read_to_string(argv_log).unwrap().lines().count(), 1);
}

#[test]
fn unsafe_plan_custody_fails_before_apply() {
    let root = TempDir::new().expect("temp root");
    let source = root.path().join("desired.toml");
    fs::write(&source, "desired = true\n").expect("write source");
    let (executable, argv_log) = fake_reconciler(root.path(), true);
    let spec = ReconcilerSpec {
        name: "owner-tool".into(),
        executable,
        source,
        privilege: ReconcilerPrivilege::User,
        protocol: "dev-tools-reconcile-v1".into(),
    };

    let error = runner().run(&spec, false).expect_err("unsafe plan");
    assert!(error.to_string().contains("unsafe plan"));
    assert!(!root.path().join("applied").exists());
    assert_eq!(fs::read_to_string(argv_log).unwrap().lines().count(), 1);
}
