//! Opt-in acceptance against an independently installed upstream release.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

struct Server {
    url: String,
    revision: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let revision = Arc::new(AtomicUsize::new(1));
        let stop = Arc::new(AtomicBool::new(false));
        let revision_child = revision.clone();
        let stop_child = stop.clone();
        let worker = thread::spawn(move || {
            while !stop_child.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("accept failed: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 8192];
                let Ok(length) = stream.read(&mut request) else {
                    continue;
                };
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = if path == "/.well-known/agent-skills/index.json" {
                    let entries = ["tracked", "missing", "new-from-source"].map(|name| json!({"name":name,"description":"Public synthetic acceptance skill","files":["SKILL.md"]}));
                    ("200 OK", json!({"skills": entries}).to_string())
                } else if let Some(name) = path
                    .strip_prefix("/.well-known/agent-skills/")
                    .and_then(|path| path.strip_suffix("/SKILL.md"))
                {
                    if ["tracked", "missing", "new-from-source"].contains(&name) {
                        ("200 OK", format!("---\nname: {name}\ndescription: Public synthetic acceptance skill\n---\nrevision {}\n", revision_child.load(Ordering::Acquire)))
                    } else {
                        ("404 Not Found", String::new())
                    }
                } else {
                    ("404 Not Found", String::new())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            url,
            revision,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn run(program: &str, prefix: &[&str], home: &Path, cwd: &Path, args: &[&str]) -> Vec<u8> {
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("DISABLE_TELEMETRY", "1")
        .env("DO_NOT_TRACK", "1")
        .env("CI", "1")
        .current_dir(cwd);
    let output = dev_tools_command::run_prepared_bounded_command_with_public_file_stdout(
        command,
        Duration::from_secs(60),
        16 * 1024 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
#[ignore = "requires SKILLS_SYNC_ACCEPTANCE_NODE and SKILLS_SYNC_ACCEPTANCE_CLI for a real released upstream CLI"]
fn real_upstream_updates_restores_and_repairs_without_expanding_selection() {
    let node = std::env::var("SKILLS_SYNC_ACCEPTANCE_NODE").expect("explicit Node executable");
    let cli = std::env::var("SKILLS_SYNC_ACCEPTANCE_CLI").expect("explicit upstream cli.mjs");
    let server = Server::new();
    let fixture = tempfile::tempdir().unwrap();
    let home = fixture.path();
    let cwd = home.join("project");
    fs::create_dir(&cwd).unwrap();
    let version = run(&node, &[&cli], home, &cwd, &["--version"]);
    assert_eq!(
        String::from_utf8_lossy(&version).trim(),
        "1.5.25",
        "qualify the pinned upstream version"
    );
    run(
        &node,
        &[&cli],
        home,
        &cwd,
        &[
            "add",
            &server.url,
            "-g",
            "-y",
            "--agent",
            "codex",
            "--skill",
            "tracked",
            "--skill",
            "missing",
        ],
    );
    let canonical = home.join(".agents/skills");
    let tracked = canonical.join("tracked/SKILL.md");
    assert!(fs::read_to_string(&tracked).unwrap().contains("revision 1"));
    let lock = home.join(".agents/.skill-lock.json");
    assert!(lock.is_file());
    // Remove only the test-owned installation while retaining upstream tracking.
    fs::remove_dir_all(canonical.join("missing")).unwrap();
    let untracked = canonical.join("untracked");
    fs::create_dir(&untracked).unwrap();
    fs::write(
        untracked.join("SKILL.md"),
        "---\nname: untracked\ndescription: untracked\n---\nunowned\n",
    )
    .unwrap();
    let app = home.join(".codex/plugins/cache/acceptance/skills/app-bundled");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("SKILL.md"), "app-owned\n").unwrap();
    let provider = format!("'{node}' '{cli}'");
    let base = [
        "--global",
        "--global-lock-file",
        lock.to_str().unwrap(),
        "--json",
        "--skills-cmd",
        &provider,
        "--agent",
        "codex",
        "--agent",
        "claude-code",
        "--adopt-policy",
        "off",
    ];
    server.revision.store(2, Ordering::Release);
    let preview = run(
        env!("CARGO_BIN_EXE_skills-sync"),
        &[],
        home,
        &cwd,
        &[&["sync", "--dry-run"][..], &base].concat(),
    );
    let preview: Value = serde_json::from_slice(&preview).unwrap();
    assert!(preview["planned_commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|plan| plan["reason"] == "update"));
    assert!(fs::read_to_string(&tracked).unwrap().contains("revision 1"));
    run(
        env!("CARGO_BIN_EXE_skills-sync"),
        &[],
        home,
        &cwd,
        &[&["sync"][..], &base].concat(),
    );
    assert!(fs::read_to_string(&tracked).unwrap().contains("revision 2"));
    assert!(fs::read_to_string(canonical.join("missing/SKILL.md"))
        .unwrap()
        .contains("revision 2"));
    assert!(home.join(".claude/skills/tracked/SKILL.md").is_file());
    assert!(!canonical.join("new-from-source").exists());
    assert!(fs::read_to_string(untracked.join("SKILL.md"))
        .unwrap()
        .ends_with("unowned\n"));
    assert_eq!(
        fs::read_to_string(app.join("SKILL.md")).unwrap(),
        "app-owned\n"
    );
    let accepted_lock = fs::read(&lock).unwrap();
    fs::remove_file(home.join(".claude/skills/tracked")).unwrap();
    server.revision.store(3, Ordering::Release);
    for _ in 0..2 {
        let repaired = run(
            env!("CARGO_BIN_EXE_skills-sync"),
            &[],
            home,
            &cwd,
            &[&["repair"][..], &base].concat(),
        );
        let repaired: Value = serde_json::from_slice(&repaired).unwrap();
        assert!(repaired["planned_commands"].as_array().unwrap().is_empty());
        assert!(fs::read_to_string(&tracked).unwrap().contains("revision 2"));
        assert_eq!(fs::read(&lock).unwrap(), accepted_lock);
        assert!(home.join(".claude/skills/tracked/SKILL.md").is_file());
    }
    run(
        &node,
        &[&cli],
        home,
        &cwd,
        &[
            "add",
            &server.url,
            "-y",
            "--agent",
            "codex",
            "--skill",
            "tracked",
        ],
    );
    let project_tracked = cwd.join(".agents/skills/tracked/SKILL.md");
    assert!(fs::read_to_string(&project_tracked)
        .unwrap()
        .contains("revision 3"));
    server.revision.store(4, Ordering::Release);
    run(
        env!("CARGO_BIN_EXE_skills-sync"),
        &[],
        home,
        &cwd,
        &[
            "sync",
            "--project",
            "--json",
            "--skills-cmd",
            &provider,
            "--agent",
            "codex",
            "--adopt-policy",
            "off",
        ],
    );
    assert!(fs::read_to_string(&project_tracked)
        .unwrap()
        .contains("revision 4"));
    assert!(fs::read_to_string(&tracked).unwrap().contains("revision 2"));
    assert_eq!(fs::read(&lock).unwrap(), accepted_lock);
    assert!(!cwd.join(".agents/skills/new-from-source").exists());
}
