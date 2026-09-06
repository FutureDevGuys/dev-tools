#![cfg(unix)]

use assert_cmd::Command;
use dev_cache::{config::Config, resources, root::RootHandle};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: RootHandle,
    config: PathBuf,
    project: PathBuf,
    intercepts: PathBuf,
    upstream: PathBuf,
    path: std::ffi::OsString,
}

#[test]
fn cargo_help_reports_configured_routing_without_opening_the_cache_root() {
    let temporary = tempfile::tempdir().unwrap();
    let alias = temporary.path().join("cargo");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_dev-cache"), &alias).unwrap();
    let real = temporary.path().join("real-cargo");
    fs::write(&real, "#!/bin/sh\nprintf 'REAL CARGO HELP\\n'\n").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    let root = temporary.path().join("uninitialized-root");
    let config_path = temporary.path().join("config.toml");
    for enabled in [true, false] {
        let config = Config {
            enabled,
            root: Some(root.clone()),
            ..Config::default()
        };
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let output = Command::new(&alias)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DEV_CACHE_CONFIG", &config_path)
            .env("DEV_CACHE_REAL_CARGO", &real)
            .arg("--help")
            .timeout(Duration::from_secs(5))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let output = std::str::from_utf8(&output).unwrap();
        let expected = if enabled {
            "dev-cache: Cargo routing configured; no cache paths opened for help/version\n"
        } else {
            "dev-cache: routing disabled\n"
        };
        assert!(output.starts_with(expected), "{output}");
        assert!(output.contains("REAL CARGO HELP"));
        assert!(!root.exists());
    }
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temporary.path().join("cache-root")).unwrap();
        let project = temporary.path().join("project");
        let intercepts = temporary.path().join("intercepts");
        let upstream = temporary.path().join("upstream");
        for path in [&project, &intercepts, &upstream] {
            fs::create_dir(path).unwrap();
        }
        for name in ["cc", "c++", "gcc", "g++", "clang", "clang++"] {
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_dev-cache"), intercepts.join(name))
                .unwrap();
            let real = upstream.join(name);
            fs::write(
                &real,
                "#!/bin/sh\nprintf 'probe-output\\n'\nprintf 'unsupported-option\\n' >&2\nexit 1\n",
            )
            .unwrap();
            fs::set_permissions(real, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let ccache = upstream.join("ccache");
        fs::write(&ccache, "#!/bin/sh\n[ -n \"$CCACHE_DIR\" ] && [ -n \"$CCACHE_TEMPDIR\" ] || exit 99\nexec \"$@\"\n").unwrap();
        fs::set_permissions(ccache, fs::Permissions::from_mode(0o755)).unwrap();
        let sccache = upstream.join("sccache");
        fs::write(
            &sccache,
            "#!/bin/sh\n[ -n \"$SCCACHE_DIR\" ] || exit 99\nexec \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(sccache, fs::Permissions::from_mode(0o755)).unwrap();
        for name in ["ccache", "sccache"] {
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_dev-cache"), intercepts.join(name))
                .unwrap();
        }
        let config_path = temporary.path().join("config.toml");
        let mut config = Config {
            root: Some(root.root.clone()),
            ..Config::default()
        };
        config.gc.min_free_bytes = 0;
        config.gc.target_free_bytes = 0;
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let path = std::env::join_paths([
            intercepts.clone(),
            upstream.clone(),
            PathBuf::from("/usr/bin"),
        ])
        .unwrap();
        Self {
            _temporary: temporary,
            root,
            config: config_path,
            project,
            intercepts,
            upstream,
            path,
        }
    }

    fn command(&self, name: &str) -> Command {
        let mut command = Command::new(self.intercepts.join(name));
        command
            .env_clear()
            .env("PATH", &self.path)
            .env("DEV_CACHE_CONFIG", &self.config)
            .current_dir(&self.project)
            .arg("-qversion")
            .timeout(Duration::from_secs(5));
        command
    }

    fn unrelated_tree(&self, files: usize) -> PathBuf {
        let path = self.root.platform_root.join("unrelated-probe-tree");
        fs::create_dir_all(&path).unwrap();
        for index in 0..files {
            fs::write(path.join(format!("entry-{index}")), b"fixture").unwrap();
        }
        path
    }
}

#[test]
fn compiler_cache_launchers_do_not_trigger_automatic_gc() {
    for name in ["ccache", "sccache"] {
        let fixture = Fixture::new();
        for _ in 0..2 {
            Command::new(fixture.intercepts.join(name))
                .env_clear()
                .env("PATH", &fixture.path)
                .env("DEV_CACHE_CONFIG", &fixture.config)
                .current_dir(&fixture.project)
                .arg(fixture.upstream.join("gcc"))
                .arg("-qversion")
                .timeout(Duration::from_secs(5))
                .assert()
                .code(1)
                .stdout("probe-output\n")
                .stderr("unsupported-option\n");
            assert!(
                !fixture
                    .root
                    .control()
                    .join("last-automatic-gc.json")
                    .exists(),
                "{name} launcher must not trigger automatic collection"
            );
        }
    }
}

#[test]
fn compiler_probes_preserve_routing_and_failure_without_triggering_automatic_gc() {
    let fixture = Fixture::new();
    for _ in 0..2 {
        for name in ["cc", "c++", "gcc", "g++", "clang", "clang++"] {
            fixture
                .command(name)
                .assert()
                .code(1)
                .stdout("probe-output\n")
                .stderr("unsupported-option\n");
            assert!(
                !fixture
                    .root
                    .control()
                    .join("last-automatic-gc.json")
                    .exists(),
                "compiler intercept must not trigger automatic collection"
            );
        }
    }
    let records = resources::list(&fixture.root).unwrap();
    assert!(
        !records.is_empty(),
        "compiler routing must remain cataloged"
    );
    assert!(records
        .iter()
        .all(|record| record.last_completed_unix.is_some()));
}

#[cfg(target_os = "linux")]
#[test]
fn compiler_probe_does_not_scan_unrelated_cache_tree_when_strace_is_available() {
    if !std::path::Path::new("/usr/bin/strace").is_file() {
        return;
    }
    let fixture = Fixture::new();
    let unrelated = fixture.unrelated_tree(32);
    let trace = fixture.project.join("file-trace");
    Command::new("/usr/bin/strace")
        .env_clear()
        .env("PATH", &fixture.path)
        .env("DEV_CACHE_CONFIG", &fixture.config)
        .current_dir(&fixture.project)
        .args(["-f", "-qq", "-e", "trace=%file", "-o"])
        .arg(&trace)
        .arg(fixture.intercepts.join("gcc"))
        .arg("-qversion")
        .timeout(Duration::from_secs(5))
        .assert()
        .code(1)
        .stdout("probe-output\n")
        .stderr("unsupported-option\n");
    assert!(
        !fs::read_to_string(trace)
            .unwrap()
            .contains(unrelated.to_str().unwrap()),
        "compiler intercept walked an unrelated cache tree"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn interval_skipped_maintenance_without_size_cap_does_not_scan_cache_tree() {
    if !std::path::Path::new("/usr/bin/strace").is_file() {
        return;
    }
    let fixture = Fixture::new();
    let unrelated = fixture.unrelated_tree(32);
    let alias = fixture.intercepts.join("npm");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_dev-cache"), &alias).unwrap();
    let real = fixture.upstream.join("npm");
    fs::write(&real, "#!/bin/sh\nprintf 'native npm\\n'\n").unwrap();
    fs::set_permissions(real, fs::Permissions::from_mode(0o755)).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fs::write(
        fixture.root.control().join("last-automatic-gc.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "last_attempt_unix": now,
            "last_success_unix": now
        }))
        .unwrap(),
    )
    .unwrap();
    let trace = fixture.project.join("npm-file-trace");
    Command::new("/usr/bin/strace")
        .env_clear()
        .env("PATH", &fixture.path)
        .env("DEV_CACHE_CONFIG", &fixture.config)
        .current_dir(&fixture.project)
        .args(["-f", "-qq", "-e", "trace=%file", "-o"])
        .arg(&trace)
        .arg(alias)
        .arg("install")
        .timeout(Duration::from_secs(5))
        .assert()
        .success()
        .stdout("native npm\n");
    assert!(
        !fs::read_to_string(trace)
            .unwrap()
            .contains(unrelated.to_str().unwrap()),
        "interval-skipped maintenance without a size cap walked unrelated cache data"
    );
}

#[test]
fn pressure_detection_preserves_free_space_and_size_thresholds() {
    let fixture = Fixture::new();
    fixture.unrelated_tree(1);
    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.max_bytes = None;
    assert!(!dev_cache::gc::pressure_needed(&fixture.root, &policy).unwrap());
    policy.max_bytes = Some(0);
    assert!(dev_cache::gc::pressure_needed(&fixture.root, &policy).unwrap());
    policy.max_bytes = Some(u64::MAX);
    assert!(!dev_cache::gc::pressure_needed(&fixture.root, &policy).unwrap());
    policy.max_bytes = None;
    policy.min_free_bytes = u64::MAX;
    assert!(dev_cache::gc::pressure_needed(&fixture.root, &policy).unwrap());
}

#[test]
#[ignore = "explicit synthetic compiler hot-path scaling measurement"]
fn compiler_probe_scaling_measurement() {
    let fixture = Fixture::new();
    for files in [0, 4_000, 12_000] {
        fixture.unrelated_tree(files);
        let mut samples = Vec::new();
        for _ in 0..9 {
            let started = Instant::now();
            fixture
                .command("gcc")
                .assert()
                .code(1)
                .stdout("probe-output\n")
                .stderr("unsupported-option\n");
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        println!(
            "unrelated_files={files} samples_us={samples:?} median_us={} max_us={}",
            samples[4], samples[8]
        );
    }
}
