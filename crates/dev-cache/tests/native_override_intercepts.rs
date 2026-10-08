#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use dev_cache::{
    config::Config,
    gc::{self, GcOverrides},
    lease::{active_resource_ids, RootLease},
    resources::{self, ResourceKind},
    root::RootHandle,
};
use wait_timeout::ChildExt;

struct Fixture {
    temporary: tempfile::TempDir,
    root: RootHandle,
    config: Config,
    config_path: PathBuf,
    project: PathBuf,
    intercepts: PathBuf,
    upstream: PathBuf,
    path: OsString,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temporary.path().join("managed-root")).unwrap();
        let project = temporary.path().join("project");
        let intercepts = temporary.path().join("intercepts");
        let upstream = temporary.path().join("upstream");
        for directory in [&project, &intercepts, &upstream] {
            fs::create_dir(directory).unwrap();
        }
        for name in [
            "sccache",
            "npm",
            "ccache",
            "zig",
            "cargo",
            "rustup",
            "dev-cache",
        ] {
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_dev-cache"), intercepts.join(name))
                .unwrap();
            let native = upstream.join(name);
            let version_probe = if matches!(name, "cargo" | "rustup") {
                "case \"$*\" in *--version) printf 'cargo 1.90.0 (fixture)\\n'; exit 0;; esac\n"
            } else {
                ""
            };
            fs::write(
                &native,
                format!(
                    "#!/bin/sh\n{version_probe}\
                 printf 'called\\n' >> \"$CALL_LOG\"\n\
                 \"$ENV_HELPER\" --exact native_environment_fixture --ignored >/dev/null || exit 97\n\
                 if [ -n \"${{READY-}}\" ]; then\n\
                   printf 'ready\\n' > \"$READY\"\n\
                   IFS= read -r release || exit 98\n\
                 fi\n\
                 printf 'native stdout\\n'\n\
                 printf '%s\\000' \"$@\"\n\
                 printf 'native stderr\\n' >&2\n\
                 exit 23\n"
                ),
            )
            .unwrap();
            fs::set_permissions(native, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut config = Config {
            root: Some(root.root.clone()),
            ..Config::default()
        };
        config.maintenance.automatic = false;
        config.sccache.cache_size = Some("2G".to_owned());
        config.gc.min_free_bytes = 0;
        config.gc.target_free_bytes = 0;
        let config_path = temporary.path().join("config.toml");
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let path = std::env::join_paths([&intercepts, &upstream]).unwrap();
        Self {
            temporary,
            root,
            config,
            config_path,
            project,
            intercepts,
            upstream,
            path,
        }
    }

    fn command(&self, name: &str, intercepted: bool) -> Command {
        let directory = if intercepted {
            &self.intercepts
        } else {
            &self.upstream
        };
        let mut command = Command::new(directory.join(name));
        command
            .env_clear()
            .env("HOME", self.temporary.path())
            .env("PATH", &self.path)
            .env("DEV_CACHE_CONFIG", &self.config_path)
            .env("ENV_SNAPSHOT", self.temporary.path().join("environment"))
            .env("ENV_HELPER", std::env::current_exe().unwrap())
            .env("CALL_LOG", self.temporary.path().join("calls"))
            .env("UNRELATED_VALUE", "spaces,=\nand a newline")
            .current_dir(&self.project);
        command
    }

    fn environment(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        fs::read(self.temporary.path().join("environment"))
            .unwrap()
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let separator = entry.iter().position(|byte| *byte == b'=').unwrap();
                (entry[..separator].to_vec(), entry[separator + 1..].to_vec())
            })
            .collect()
    }

    fn assert_no_routed_state(&self) {
        assert!(resources::list(&self.root).unwrap().is_empty());
        assert!(active_resource_ids(&self.root).unwrap().is_empty());
        assert_eq!(
            fs::read_dir(self.root.control().join("leases"))
                .unwrap()
                .count(),
            0
        );
        assert!(RootLease::try_exclusive(&self.root).unwrap().is_some());
    }

    fn assert_unchanged(&self, name: &str, args: &[OsString], overrides: &[(&str, &OsStr)]) {
        let command = |intercepted| {
            let mut command = self.command(name, intercepted);
            command.args(args).envs(overrides.iter().copied());
            command
        };
        self.assert_same_as_native(command(false), command(true));
    }

    fn assert_same_as_native(&self, direct: Command, delegated: Command) {
        let run = |command| {
            assert_cmd::Command::from_std(command)
                .timeout(Duration::from_secs(5))
                .assert()
                .code(23)
                .get_output()
                .clone()
        };
        let direct = run(direct);
        let environment = self.environment();
        let delegated = run(delegated);
        assert_eq!(
            delegated.stdout, direct.stdout,
            "native argv/stdout changed"
        );
        assert_eq!(delegated.stderr, direct.stderr, "native stderr changed");
        assert_eq!(
            self.environment(),
            environment,
            "native environment changed"
        );
        self.assert_no_routed_state();
        assert_eq!(
            fs::read(self.temporary.path().join("calls")).unwrap(),
            b"called\ncalled\n"
        );
    }

    fn start(&self, name: &str, overrides: &[(&str, &OsStr)]) -> RunningChild {
        let ready = self.temporary.path().join("ready");
        let mut command = if name == "exec-sccache" {
            let mut command = self.command("dev-cache", true);
            command
                .args(["exec", "sccache", "--"])
                .arg(self.upstream.join("sccache"));
            command
        } else {
            self.command(name, true)
        };
        command
            .arg("--show-stats")
            .envs(overrides.iter().copied())
            .env("READY", &ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut running = RunningChild(Some(command.spawn().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() {
            assert!(Instant::now() < deadline, "native tool did not start");
            assert!(
                running.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "intercept exited before native delegation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        running
    }
}

struct RunningChild(Option<Child>);

impl RunningChild {
    fn finish(mut self) -> Output {
        let child = self.0.as_mut().unwrap();
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
        assert!(child
            .wait_timeout(Duration::from_secs(5))
            .unwrap()
            .is_some());
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(23));
        assert_eq!(output.stdout, b"native stdout\n--show-stats\0");
        assert_eq!(output.stderr, b"native stderr\n");
        output
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn sccache_native_directory_preserves_native_arguments_environment_streams_and_exit() {
    for args in [
        vec![OsString::from("--version")],
        vec![OsString::from("--show-stats")],
        vec![
            OsString::from("rustc"),
            OsString::from("-vV"),
            OsString::from("spaces and\na newline"),
            OsString::new(),
            OsString::from_vec(b"non-utf8-\xff".to_vec()),
        ],
    ] {
        let fixture = Fixture::new();
        let native = fixture.temporary.path().join("native cache");
        let overrides = [
            ("SCCACHE_DIR", native.as_os_str()),
            ("SCCACHE_CACHE_SIZE", OsStr::new("1G")),
            ("DEV_CACHE_PROVENANCE", OsStr::new("unmanaged provenance")),
        ];
        fixture.assert_unchanged("sccache", &args, &overrides);
        assert!(
            !native.exists(),
            "Dev Cache must not create the native cache"
        );
    }
}

#[test]
fn sccache_unroutable_persistent_configuration_delegates_unchanged() {
    for contents in [
        "[cache.redis]\nurl = 'redis://example.invalid'\n",
        "invalid toml [",
    ] {
        let fixture = Fixture::new();
        let config = fixture.temporary.path().join("sccache.toml");
        fs::write(&config, contents).unwrap();
        fixture.assert_unchanged(
            "sccache",
            &["--show-stats".into()],
            &[("SCCACHE_CONF", config.as_os_str())],
        );
        assert_eq!(fs::read_to_string(config).unwrap(), contents);
    }
}

#[test]
fn other_fully_overridden_generic_intercepts_delegate_unchanged() {
    for (name, variables) in [
        ("npm", vec!["npm_config_cache"]),
        ("ccache", vec!["CCACHE_DIR", "CCACHE_TEMPDIR"]),
        ("zig", vec!["ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR"]),
    ] {
        let fixture = Fixture::new();
        let native = fixture.temporary.path().join("native cache");
        let overrides: Vec<_> = variables
            .iter()
            .map(|name| (*name, native.as_os_str()))
            .collect();
        fixture.assert_unchanged(name, &["native-operation".into()], &overrides);
        assert!(!native.exists());
    }
}

#[test]
fn empty_resource_delegation_releases_setup_without_publishing_activity() {
    for command in ["sccache", "exec-sccache", "cargo"] {
        let fixture = Fixture::new();
        let native = fixture.temporary.path().join("native cache");
        let child = fixture.start(command, &[("SCCACHE_DIR", native.as_os_str())]);
        fixture.assert_no_routed_state();
        let environment = fixture.environment();
        assert_eq!(
            environment.get(b"SCCACHE_DIR".as_slice()),
            Some(&native.as_os_str().as_encoded_bytes().to_vec())
        );
        for name in [
            b"SCCACHE_SERVER_PORT".as_slice(),
            b"DEV_CACHE_PROVENANCE".as_slice(),
            b"RUSTC_WRAPPER".as_slice(),
            b"SCCACHE_CACHE_SIZE".as_slice(),
        ] {
            assert!(!environment.contains_key(name));
        }
        child.finish();
        fixture.assert_no_routed_state();
    }
}

#[test]
fn nonempty_routing_keeps_resource_specific_collection_protection() {
    for (name, kind, variable) in [
        ("sccache", ResourceKind::SccacheLocal, None),
        ("zig", ResourceKind::ZigLocal, Some("ZIG_GLOBAL_CACHE_DIR")),
    ] {
        let fixture = Fixture::new();
        let native = fixture.temporary.path().join("native cache");
        let overrides: Vec<_> = variable
            .into_iter()
            .map(|name| (name, native.as_os_str()))
            .collect();
        let child = fixture.start(name, &overrides);
        let records = resources::list(&fixture.root).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, kind);
        assert!(records[0].last_completed_unix.is_none());
        let ids = BTreeSet::from([records[0].resource_id.clone()]);
        assert_eq!(active_resource_ids(&fixture.root).unwrap(), ids);
        assert_eq!(
            fs::read_dir(fixture.root.control().join("leases"))
                .unwrap()
                .count(),
            1
        );
        let routed = resources::absolute_path(&fixture.root, &records[0]).unwrap();
        let sentinel = routed.join("keep-while-active");
        fs::write(&sentinel, b"active cache").unwrap();
        let report = gc::collect(
            &fixture.root,
            &fixture.config.gc,
            120,
            &GcOverrides {
                stale_after_days: Some(0),
                ..GcOverrides::default()
            },
            true,
        )
        .unwrap();
        assert!(report.abstentions.iter().any(|item| {
            item.resource_id.as_ref() == Some(&records[0].resource_id)
                && item.reason.contains("active routed command")
        }));
        assert_eq!(fs::read(&sentinel).unwrap(), b"active cache");
        assert!(!native.exists());
        child.finish();
        assert!(active_resource_ids(&fixture.root).unwrap().is_empty());
        let completed = resources::list(&fixture.root).unwrap();
        assert!(completed[0].last_completed_unix.is_some());
    }
}

#[test]
fn empty_active_leases_remain_rejected() {
    let fixture = Fixture::new();
    let setup = RootLease::shared(&fixture.root, "empty-activity-regression").unwrap();
    assert!(setup.into_active(&[]).is_err());
    fixture.assert_no_routed_state();
}

#[test]
fn unroutable_intercept_does_not_turn_root_identity_failures_into_delegation() {
    let fixture = Fixture::new();
    let mut marker = fixture.root.marker.clone();
    marker.canonical_path = fixture.temporary.path().join("different-root");
    fs::write(
        fixture.root.root.join(".dev-cache-root.json"),
        serde_json::to_vec(&marker).unwrap(),
    )
    .unwrap();
    let mut command = fixture.command("sccache", true);
    command
        .arg("--show-stats")
        .env("SCCACHE_DIR", fixture.temporary.path().join("native cache"));
    assert_cmd::Command::from_std(command)
        .timeout(Duration::from_secs(5))
        .assert()
        .code(10);
    assert!(!fixture.temporary.path().join("calls").exists());
}

#[test]
fn explicit_exec_without_resources_delegates_unchanged() {
    for (adapter, variables) in [
        ("sccache", vec!["SCCACHE_DIR"]),
        ("npm", vec!["npm_config_cache"]),
        ("temp", vec!["TMPDIR", "TEMP", "TMP"]),
    ] {
        let fixture = Fixture::new();
        let native = fixture.temporary.path().join("native cache");
        let overrides: Vec<_> = variables
            .iter()
            .map(|name| (*name, native.as_os_str()))
            .collect();
        let args = ["--show-stats", "argument with spaces", ""];
        let mut direct = fixture.command("sccache", false);
        direct.args(args).envs(overrides.iter().copied());
        let mut delegated = fixture.command("dev-cache", true);
        delegated
            .args(["exec", adapter, "--"])
            .arg(fixture.upstream.join("sccache"))
            .args(args)
            .envs(overrides.iter().copied());
        fixture.assert_same_as_native(direct, delegated);
        assert!(!native.exists());
    }
}

#[test]
fn legacy_cargo_without_sccache_resources_preserves_native_delegation() {
    for command in ["cargo", "rustup"] {
        for variable in ["SCCACHE_DIR", "SCCACHE_BUCKET"] {
            let fixture = Fixture::new();
            let native = fixture.temporary.path().join("native cache");
            let args: Vec<_> = if command == "cargo" {
                vec!["check".into(), "argument with spaces".into()]
            } else {
                vec![
                    "run".into(),
                    "stable".into(),
                    "cargo".into(),
                    "check".into(),
                    "argument with spaces".into(),
                ]
            };
            fixture.assert_unchanged(command, &args, &[(variable, native.as_os_str())]);
            assert!(!native.exists());
        }
    }
}

#[test]
#[ignore = "subprocess-only native environment capture fixture"]
fn native_environment_fixture() {
    let destination = std::env::var_os("ENV_SNAPSHOT").expect("native fixture destination");
    let mut environment = Vec::new();
    for (name, value) in std::env::vars_os() {
        environment.extend(name.into_vec());
        environment.push(b'=');
        environment.extend(value.into_vec());
        environment.push(0);
    }
    fs::write(destination, environment).unwrap();
}
