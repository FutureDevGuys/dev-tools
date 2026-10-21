//! Read-only real executable acceptance for damaged run history.
use serde_json::{Value, json};
use std::time::Duration;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use tempfile::TempDir;
use wait_timeout::ChildExt;

struct Fixture {
    root: TempDir,
    config: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let config = root.path().join("config.toml");
        fs::create_dir(root.path().join("runs")).unwrap();
        fs::write(
            &config,
            format!(
                "[logging]\nrun_dir={:?}\n",
                root.path().join("runs").display().to_string()
            ),
        )
        .unwrap();
        Self { root, config }
    }
    fn run(&self, args: &[&str]) -> Output {
        let mut child = Command::new(
            std::env::var_os("UPDATE_ALL_INSPECTION_TEST_BINARY")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all"))),
        )
        .args(["--config"])
        .arg(&self.config)
        .args(args)
        .env("HOME", self.root.path())
        .env("PATH", "")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
        if child
            .wait_timeout(Duration::from_secs(5))
            .unwrap()
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
            panic!("read-only command exceeded timeout");
        }
        child.wait_with_output().unwrap()
    }
    fn entry(&self, name: &str, artifact: &str) -> PathBuf {
        let dir = self.root.path().join("runs").join(name);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("run-meta.json"), json!({"schema_version":1,"run_id":name,"display_name":name,"created_unix_ms":1,"updated_unix_ms":1,"status":"completed","run_dir":dir,"pid":1,"host_os":"linux","ui_mode":"plain","engine_mode":"async","selected_tasks":["npm"]}).to_string()).unwrap();
        fs::write(dir.join("run.json"), artifact).unwrap();
        dir
    }
}

#[test]
fn corrupt_neighbor_does_not_hide_healthy_history() {
    let f = Fixture::new();
    f.entry("healthy", r#"{"tasks":[],"exit_code":0}"#);
    let bad = f.entry("broken", "");
    fs::write(bad.join("run-meta.json"), "{").unwrap();
    let out = f.run(&["restore", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["run_id"], "healthy");
    assert!(String::from_utf8_lossy(&out.stderr).contains("inspect"));
    assert!(f.run(&["resume", "healthy", "--json"]).status.success());
}

#[test]
fn inspection_reports_unknown_without_rewriting_evidence() {
    let f = Fixture::new();
    let bad = f.entry("broken", "null");
    let original = fs::read(bad.join("run-meta.json")).unwrap();
    let before = snapshot(f.root.path());
    let out = f.run(&["runs", "inspect", "broken", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["schema"], "update-all-run-inspection-v1");
    assert_eq!(report["runs"][0]["run_artifact_status"], "malformed");
    assert!(report["runs"][0]["task_count"].is_null());
    assert_eq!(fs::read(bad.join("run-meta.json")).unwrap(), original);
    assert_eq!(fs::read_to_string(bad.join("run.json")).unwrap(), "null");
    let restored: Value = serde_json::from_slice(&f.run(&["restore", "--json"]).stdout).unwrap();
    assert!(restored[0]["issue_count"].is_null());
    let plain = f.run(&["resume", "broken"]);
    assert!(String::from_utf8_lossy(&plain.stdout).contains("Issue count: ?"));
    assert_eq!(snapshot(f.root.path()), before);
}

#[test]
fn wrong_shaped_artifacts_are_not_successful_empty_runs() {
    let f = Fixture::new();
    for (i, artifact) in [
        "null",
        "{}",
        r#"{"tasks":"oops"}"#,
        r#"{"tasks":[null]}"#,
        r#"{"tasks":[{"status":"invented"}]}"#,
    ]
    .iter()
    .enumerate()
    {
        f.entry(&format!("bad-{i}"), artifact);
    }
    let out = f.run(&["restore", "--json"]);
    assert!(out.status.success());
    let rows: Value = serde_json::from_slice(&out.stdout).unwrap();
    for row in rows.as_array().unwrap() {
        assert_eq!(row["run_json_status"], "malformed");
        assert!(row["task_count"].is_null());
    }
}

#[test]
fn active_finalizing_metadata_and_warning_skips_remain_truthful() {
    let f = Fixture::new();
    let dir = f.entry("active", r#"{"tasks":[{"status":"skipped","advisories":[{"severity":"warning","code":"deferred"}]}]}"#);
    let path = dir.join("run-meta.json");
    let mut metadata: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata["status"] = json!("finalizing");
    fs::write(&path, metadata.to_string()).unwrap();
    let out = f.run(&["resume", "active", "--json"]);
    assert!(out.status.success());
    let row: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(row["status"], "finalizing");
    assert_eq!(row["issue_count"], 1);
    fs::write(
        dir.join("run.json"),
        r#"{"tasks":[{"status":"skipped","advisories":"damaged"}]}"#,
    )
    .unwrap();
    let out = f.run(&["resume", "active", "--json"]);
    let row: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(row["issue_count"].is_null());
}

#[test]
fn unsupported_and_oversized_evidence_is_unknown() {
    let f = Fixture::new();
    let dir = f.entry("future", r#"{"schema_version":99,"tasks":[]}"#);
    let path = dir.join("run-meta.json");
    let mut metadata: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata["schema_version"] = json!(99);
    fs::write(&path, metadata.to_string()).unwrap();
    let out = f.run(&["runs", "inspect", "future", "--json"]);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["runs"][0]["metadata_status"], "unsupported");
    assert_eq!(report["runs"][0]["run_artifact_status"], "unsupported");
    assert!(report["runs"][0]["run_id"].is_null());
    let file = fs::File::create(dir.join("run.json")).unwrap();
    file.set_len(9 * 1024 * 1024).unwrap();
    let out = f.run(&["runs", "inspect", "--json"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["runs"][0]["run_artifact_status"], "oversized");
}

#[test]
#[cfg(unix)]
fn symlinks_and_fifos_are_not_followed_or_opened() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let dir = f.entry("unsafe", "");
    fs::remove_file(dir.join("run.json")).unwrap();
    symlink("/dev/zero", dir.join("run.json")).unwrap();
    fs::remove_file(dir.join("run-meta.json")).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let fifo = std::ffi::CString::new(dir.join("run-meta.json").as_os_str().as_bytes()).unwrap();
    // SAFETY: the temporary path is a live NUL-terminated CString.
    #[allow(unsafe_code)]
    let created = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
    assert_eq!(created, 0);
    let out = f.run(&["runs", "inspect", "--json"]);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["runs"][0]["metadata_status"], "unsafe");
    assert_eq!(report["runs"][0]["run_artifact_status"], "unsafe");
    assert!(!f.run(&["rename", "unsafe", "new-name"]).status.success());
    assert!(
        fs::symlink_metadata(dir.join("run.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

fn snapshot(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>, u32)> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = fs::symlink_metadata(&path).unwrap();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let mode = u32::from(metadata.permissions().readonly());
        let bytes = if metadata.is_file() {
            fs::read(&path).unwrap()
        } else {
            Vec::new()
        };
        entries.push((path.clone(), bytes, mode));
        if metadata.is_dir() {
            entries.extend(snapshot(&path));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

#[test]
fn exact_directory_inspection_works_beside_large_unrelated_history() {
    let f = Fixture::new();
    f.entry("target", "null");
    for index in 0..9 {
        let dir = f.entry(&format!("large-{index}"), "");
        fs::File::create(dir.join("run.json"))
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
    }
    assert!(!f.run(&["runs", "inspect", "--json"]).status.success());
    let out = f.run(&["runs", "inspect", "target", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["runs"].as_array().unwrap().len(), 1);
}
