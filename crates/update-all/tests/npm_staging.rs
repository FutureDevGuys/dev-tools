//! The standalone CLI must never delete possible recovery material by name.
#![cfg(unix)]
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;
use wait_timeout::ChildExt;

fn provider() -> &'static Path {
    static FIXTURE: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &FIXTURE
        .get_or_init(|| {
            let temp = TempDir::new().unwrap();
            let binary = temp.path().join("provider");
            assert!(Command::new("rustc")
                .args(["--edition=2024", "-C", "debuginfo=0"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/npm_staging.rs"
                ))
                .arg("-o")
                .arg(&binary)
                .status()
                .unwrap()
                .success());
            (temp, binary)
        })
        .1
}

fn exercise(engine: &str, canonical: bool, success: bool, retained: bool) -> (TempDir, Value) {
    let home = TempDir::new().unwrap();
    let bin = home.path().join("bin");
    let root = home.path().join("lib/node_modules");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(root.join("@scope")).unwrap();
    fs::copy(provider(), bin.join("npm")).unwrap();
    if canonical {
        for package in ["first", "@scope/second"] {
            fs::create_dir_all(root.join(package)).unwrap();
            fs::write(
                root.join(package).join("package.json"),
                format!("{{\"name\":\"{package}\",\"version\":\"1.0.0\"}}"),
            )
            .unwrap();
        }
    }
    let retained_paths = [
        ".first-retained",
        "@scope/.second-retained",
        ".unrelated-not-npm",
        ".notes",
    ];
    if retained {
        for path in retained_paths {
            fs::create_dir_all(root.join(path)).unwrap();
            fs::write(root.join(path).join("contents"), "only retained copy").unwrap();
        }
        let outside = home.path().join("outside");
        fs::create_dir_all(outside.join(".outside-only")).unwrap();
        fs::write(outside.join(".outside-only/contents"), "untouched").unwrap();
        symlink(&outside, root.join(".linked-retained")).unwrap();
        symlink(&outside, root.join("@linked")).unwrap();
    }
    let config = home.path().join("config/update-all");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"1\"\n[tasks.npm_install]\nretries=2\nretry_backoff_secs=0\ntimeout_secs=5\n")).unwrap();
    let executable = std::env::var_os("UPDATE_ALL_STAGING_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
    let mut child = Command::new(executable)
        .args(["--plain", "--completions", "off", "--only", "builtin/npm"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("PATH", &bin)
        .env("STAGING_FIXTURE_ROOT", home.path())
        .env(
            "STAGING_FIXTURE_MODE",
            if success { "success" } else { "failure" },
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if child
        .wait_timeout(Duration::from_secs(20))
        .unwrap()
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture run timed out");
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        home.path().join("mutation").exists(),
        "provider mutation not reached: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.success(),
        success,
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if retained {
        for path in retained_paths {
            assert_eq!(
                fs::read_to_string(root.join(path).join("contents"))
                    .ok()
                    .as_deref(),
                Some("only retained copy"),
                "lost {path}; canonical={canonical} success={success} engine={engine}"
            );
        }
        assert!(root
            .join(".linked-retained")
            .symlink_metadata()
            .unwrap()
            .is_symlink());
        assert!(root
            .join("@linked")
            .symlink_metadata()
            .unwrap()
            .is_symlink());
        assert_eq!(
            fs::read_to_string(home.path().join("outside/.outside-only/contents")).unwrap(),
            "untouched"
        );
    }
    let run = fs::read_dir(home.path().join("state/update-all/runs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    let artifact = serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    (home, artifact)
}

#[test]
fn npm_preserves_scoped_unscoped_and_unrelated_hidden_directories() {
    for engine in ["sync", "async"] {
        for canonical in [false, true] {
            for success in [false, true] {
                let (_home, artifact) = exercise(engine, canonical, success, true);
                let advisories = artifact["tasks"][0]["advisories"].as_array().unwrap();
                let notice = advisories
                    .iter()
                    .find(|a| a["code"] == "npm-hidden-directories-preserved")
                    .expect("preservation notice");
                assert_eq!(notice["blocks_dependents"], false);
                assert!(
                    !notice.to_string().contains(".outside-only"),
                    "scope symlink was followed"
                );
                assert_eq!(
                    artifact["tasks"][0]["status"],
                    if success { "completed" } else { "failed" }
                );
                if !success {
                    assert!(advisories
                        .iter()
                        .any(|a| a["code"] == "npm-storage-exhausted"));
                    let calls = fs::read_to_string(_home.path().join("calls")).unwrap();
                    assert_eq!(
                        calls
                            .lines()
                            .filter(|line| line.starts_with("install "))
                            .count(),
                        1
                    );
                }
            }
        }
    }
}

#[test]
fn npm_ordinary_success_does_not_report_retained_staging() {
    for engine in ["sync", "async"] {
        let (_home, artifact) = exercise(engine, true, true, false);
        assert!(!artifact["tasks"][0]["advisories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["code"] == "npm-hidden-directories-preserved"));
    }
}
