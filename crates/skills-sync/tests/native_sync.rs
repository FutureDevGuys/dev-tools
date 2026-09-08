#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            directory: tempfile::tempdir().unwrap(),
        };
        let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args(["--edition=2021", "--crate-name", "upstream_fixture"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upstream.rs"))
            .arg("-o")
            .arg(fixture.home().join("provider"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        fs::create_dir_all(fixture.home().join(".agents/skills/tracked")).unwrap();
        fs::write(
            fixture.home().join(".agents/skills/tracked/SKILL.md"),
            "original payload\n",
        )
        .unwrap();
        fixture.lock(&["tracked"]);
        fixture
    }
    fn home(&self) -> &Path {
        self.directory.path()
    }
    fn lock(&self, names: &[&str]) {
        let skills: serde_json::Map<String, Value> = names.iter().map(|name| ((*name).into(), json!({"source":"example/skills", "sourceType":"github", "sourceUrl":"https://github.com/example/skills.git", "skillPath":format!("skills/{name}/SKILL.md"), "skillFolderHash":"fixture-hash"}))).collect();
        fs::write(
            self.home().join(".agents/skills-lock.json"),
            serde_json::to_vec(&json!({"version":3,"skills":skills})).unwrap(),
        )
        .unwrap();
        let alias = self.home().join(".agents/.skill-lock.json");
        if fs::symlink_metadata(&alias).is_err() {
            std::os::unix::fs::symlink("skills-lock.json", alias).unwrap();
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_skills-sync"))
            .env_clear()
            .env("HOME", self.home())
            .env("TMPDIR", self.home())
            .env("PATH", "/nonexistent")
            .current_dir(self.home())
            .args(args)
            .args(["--global", "--json", "--skills-cmd"])
            .arg(self.home().join("provider"))
            .output()
            .unwrap()
    }
    fn payload(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(output.status.success(), "{:?}", output);
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.home().join("provider-calls")).unwrap()
    }
}

#[test]
fn repair_restores_explicit_agent_links_without_reinstalling_payloads() {
    let fixture = Fixture::new();
    fs::write(fixture.home().join("reject-add"), "").unwrap();
    let before = fs::read(fixture.home().join(".agents/skills/tracked/SKILL.md")).unwrap();
    let args = [
        "repair",
        "--adopt-policy",
        "off",
        "--agent",
        "codex",
        "--agent",
        "claude-code",
    ];
    let preview = fixture.payload(&[&args[..], &["--dry-run"]].concat());
    assert!(preview["planned_commands"].as_array().unwrap().is_empty());
    assert_eq!(
        preview["planned_agent_repairs"].as_array().unwrap().len(),
        1
    );
    assert!(!fixture.home().join(".claude").exists());
    let applied = fixture.payload(&args);
    assert_eq!(
        applied["applied_agent_repairs"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        fs::read(fixture.home().join(".agents/skills/tracked/SKILL.md")).unwrap(),
        before
    );
    assert_eq!(
        fs::canonicalize(fixture.home().join(".claude/skills/tracked")).unwrap(),
        fs::canonicalize(fixture.home().join(".agents/skills/tracked")).unwrap()
    );
    let repeat = fixture.payload(&args);
    assert!(repeat["planned_commands"].as_array().unwrap().is_empty());
    assert!(repeat["planned_agent_repairs"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!fixture.calls().contains("\"add\""));
    assert!(!fixture.calls().contains("\"update\""));
}

#[test]
fn sync_updates_installed_tracking_restores_missing_and_preserves_other_owners() {
    let fixture = Fixture::new();
    fixture.lock(&["tracked", "missing"]);
    let extra = fixture.home().join(".agents/skills/untracked");
    let app = fixture
        .home()
        .join(".codex/plugins/cache/example/skills/app-bundled");
    for path in [&extra, &app] {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("SKILL.md"), "unowned payload\n").unwrap();
    }
    let args = ["sync", "--agent", "codex", "--agent", "claude-code"];
    let preview = fixture.payload(&[&args[..], &["--dry-run"]].concat());
    assert!(preview["planned_commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|plan| plan["reason"] == "update"));
    assert!(!fixture.calls().contains("\"update\""));
    fixture.payload(&args);
    assert_eq!(
        fs::read_to_string(fixture.home().join(".agents/skills/tracked/SKILL.md")).unwrap(),
        "updated payload\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.home().join(".agents/skills/missing/SKILL.md")).unwrap(),
        "restored payload\n"
    );
    for path in [&extra, &app] {
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "unowned payload\n"
        );
    }
    assert!(fixture
        .home()
        .join(".claude/skills/tracked/SKILL.md")
        .is_file());
    assert!(!fixture
        .home()
        .join(".agents/skills/new-from-source")
        .exists());
}

#[test]
fn failed_update_stops_before_restore_or_link_mutation() {
    let fixture = Fixture::new();
    fixture.lock(&["tracked", "missing"]);
    fs::write(fixture.home().join("fail-update"), "").unwrap();
    let output = fixture.run(&["sync"]);
    assert!(!output.status.success());
    let payload: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(payload["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error
            .as_str()
            .unwrap()
            .contains("upstream tracked update failed")));
    assert!(!fixture.home().join(".agents/skills/missing").exists());
    assert!(!fixture.calls().contains("\"add\""));
}

#[test]
fn detached_lock_cannot_redirect_an_upstream_update() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.home().join(".agents/.skill-lock.json")).unwrap();
    fs::write(
        fixture.home().join(".agents/.skill-lock.json"),
        b"{\"version\":3,\"skills\":{}}",
    )
    .unwrap();
    let before = fs::read(fixture.home().join(".agents/skills/tracked/SKILL.md")).unwrap();
    let output = fixture.run(&["sync"]);
    assert!(!output.status.success());
    assert!(!fixture.calls().contains("\"update\""));
    assert_eq!(
        fs::read(fixture.home().join(".agents/skills/tracked/SKILL.md")).unwrap(),
        before
    );
}

#[test]
fn old_provider_is_rejected_before_it_can_ignore_update_selection_flags() {
    let fixture = Fixture::new();
    fs::write(fixture.home().join("provider-version"), "1.0.0\n").unwrap();
    let output = fixture.run(&["sync"]);
    assert!(!output.status.success());
    assert!(!fixture.calls().contains("\"update\""));
}

#[test]
fn status_and_sync_preview_do_not_update_or_change_payloads() {
    let fixture = Fixture::new();
    let payload_path = fixture.home().join(".agents/skills/tracked/SKILL.md");
    let lock_path = fixture.home().join(".agents/skills-lock.json");
    let payload = fs::read(&payload_path).unwrap();
    let lock = fs::read(&lock_path).unwrap();
    for args in [
        &["status", "--apply"][..],
        &["sync", "--dry-run", "--apply"][..],
    ] {
        fixture.payload(args);
        assert_eq!(fs::read(&payload_path).unwrap(), payload);
        assert_eq!(fs::read(&lock_path).unwrap(), lock);
        assert!(!fixture.home().join(".claude").exists());
    }
    assert!(!fixture.calls().contains("\"update\""));
    assert!(!fixture.calls().contains("\"add\""));
}

#[test]
fn update_deadline_stops_the_provider_before_later_mutations() {
    let fixture = Fixture::new();
    fixture.lock(&["tracked", "missing"]);
    fs::write(fixture.home().join("hang-update"), "").unwrap();
    let output = fixture.run(&["sync", "--command-timeout", "1"]);
    assert!(!output.status.success());
    assert!(
        fixture.home().join("update-entered").is_file(),
        "timeout must reach the provider: {:?}",
        output
    );
    assert!(!fixture.home().join("update-overran").exists());
    assert!(!fixture.home().join(".agents/skills/missing").exists());
    let payload: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(payload["errors"].to_string().contains("timed out"));
}

#[test]
fn interrupt_running_update_prevents_later_mutations_and_returns_130() {
    let fixture = Fixture::new();
    fixture.lock(&["tracked", "missing"]);
    fs::write(fixture.home().join("hang-update"), "").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
        .env_clear()
        .env("HOME", fixture.home())
        .env("PATH", "/nonexistent")
        .current_dir(fixture.home())
        .args(["sync", "--global", "--json", "--skills-cmd"])
        .arg(fixture.home().join("provider"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !fixture.home().join("update-entered").exists() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("provider never entered: {output:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(Command::new("/bin/kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130), "{output:?}");
    assert!(!fixture.home().join("update-overran").exists());
    assert!(!fixture.home().join(".agents/skills/missing").exists());
    assert!(!fixture.calls().contains("\"add\""));
}

#[test]
fn ambiguous_lock_names_are_rejected_before_any_provider_update() {
    let fixture = Fixture::new();
    fixture.lock(&["tracked", "TRACKED"]);
    let output = fixture.run(&["sync"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(!fixture.calls().contains("\"update\""));
}

#[test]
fn repair_replaces_a_broken_agent_link_in_one_pass_without_upstream_add() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.home().join(".claude/skills")).unwrap();
    std::os::unix::fs::symlink(
        "/nonexistent/skills-sync-fixture",
        fixture.home().join(".claude/skills/tracked"),
    )
    .unwrap();
    fs::write(fixture.home().join("reject-add"), "").unwrap();
    fixture.payload(&[
        "repair",
        "--adopt-policy",
        "off",
        "--agent",
        "codex",
        "--agent",
        "claude-code",
    ]);
    assert!(fixture
        .home()
        .join(".claude/skills/tracked/SKILL.md")
        .is_file());
    assert!(!fixture.calls().contains("\"add\""));
}
