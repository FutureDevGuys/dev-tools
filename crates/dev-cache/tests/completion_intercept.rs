use std::ffi::OsString;

use dev_cache::adapter::Adapter;
use dev_cache::dispatch::{classify_invocation, Dispatch};

fn classify(args: &[&str]) -> Dispatch {
    classify_invocation("uv", &args.iter().map(OsString::from).collect::<Vec<_>>())
}

#[test]
fn uv_completion_skips_only_recognized_global_options() {
    for option in [
        "--no-cache",
        "--managed-python",
        "--no-managed-python",
        "--no-python-downloads",
        "--quiet",
        "--verbose",
        "--system-certs",
        "--native-tls",
        "--offline",
        "--no-progress",
        "--no-config",
        "--help",
        "--version",
        "-n",
        "-q",
        "-vv",
        "-nqv",
        "-h",
        "-V",
    ] {
        assert_eq!(
            classify(&[option, "generate-shell-completion", "zsh"]),
            Dispatch::Delegate,
            "{option}"
        );
    }
    for option in [
        "--cache-dir",
        "--color",
        "--allow-insecure-host",
        "--directory",
        "--project",
        "--config-file",
    ] {
        for args in [
            vec![option, "value with spaces", "generate-shell-completion"],
            vec![
                &format!("{option}=value with spaces"),
                "generate-shell-completion",
            ],
        ] {
            assert_eq!(classify(&args), Dispatch::Delegate, "{args:?}");
        }
        assert_eq!(classify(&[option]), Dispatch::Adapter(Adapter::Uv));
        assert_eq!(
            classify(&[option, "generate-shell-completion", "run"]),
            Dispatch::Adapter(Adapter::Uv)
        );
        assert_eq!(
            classify(&[&format!("{option}=generate-shell-completion"), "run"]),
            Dispatch::Adapter(Adapter::Uv)
        );
    }
    assert_eq!(
        classify(&[
            "--quiet",
            "--offline",
            "--color=never",
            "generate-shell-completion",
            "bad-shell"
        ]),
        Dispatch::Delegate
    );
    assert_eq!(
        classify_invocation(
            "UV.EXE",
            &["--quiet".into(), "generate-shell-completion".into()]
        ),
        Dispatch::Delegate
    );
}

#[test]
fn completion_words_in_workloads_and_unknown_grammars_keep_routing() {
    for args in [
        vec![],
        vec!["--quiet"],
        vec!["--offline", "run", "generate-shell-completion"],
        vec!["--quiet", "tool", "run", "generate-shell-completion"],
        vec!["--quiet", "--", "generate-shell-completion"],
        vec!["--directory", "generate-shell-completion"],
        vec!["--unknown", "generate-shell-completion"],
        vec!["-qx", "generate-shell-completion"],
        vec!["--quiet=true", "generate-shell-completion"],
        vec!["--preview-features", "generate-shell-completion"],
        vec!["--generate-shell-completion", "bash"],
        vec!["generate-shell-completion-extra", "bash"],
        vec!["", "generate-shell-completion"],
        vec!["-", "generate-shell-completion"],
    ] {
        assert_eq!(classify(&args), Dispatch::Adapter(Adapter::Uv), "{args:?}");
    }
    assert_eq!(
        classify_invocation(
            "uvx",
            &["--quiet".into(), "--generate-shell-completion".into()]
        ),
        Dispatch::Adapter(Adapter::Uv)
    );
}

#[cfg(unix)]
#[test]
fn option_path_values_are_not_required_to_be_unicode() {
    use std::os::unix::ffi::OsStringExt;
    for args in [
        vec![
            "--directory".into(),
            OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec()),
            "generate-shell-completion".into(),
        ],
        vec![
            OsString::from_vec(b"--directory=/tmp/non-utf8-\xff".to_vec()),
            "generate-shell-completion".into(),
        ],
    ] {
        assert_eq!(classify_invocation("uv", &args), Dispatch::Delegate);
    }
    assert_eq!(
        classify_invocation(
            "uv",
            &[
                OsString::from_vec(vec![0xff]),
                "generate-shell-completion".into()
            ]
        ),
        Dispatch::Adapter(Adapter::Uv)
    );
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Output;
    use std::time::{Duration, SystemTime};

    use dev_cache::config::Config;
    use dev_cache::lease::RootLease;
    use dev_cache::root::RootHandle;

    struct Fixture {
        home: tempfile::TempDir,
        intercept: PathBuf,
        path: OsString,
        config: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            let intercept = home.path().join("intercepts");
            let upstream = home.path().join("upstream");
            fs::create_dir(&intercept).unwrap();
            fs::create_dir(&upstream).unwrap();
            for name in ["uv", "uvx"] {
                symlink(env!("CARGO_BIN_EXE_dev-cache"), intercept.join(name)).unwrap();
                let real = upstream.join(name);
                fs::write(&real, "#!/bin/sh\nprintf '%s\\000' \"$@\"\nprintf '%s\\n' \"${UV_CACHE_DIR-unset}\" \"${DEV_CACHE_PROVENANCE-unset}\" >&2\nexit \"$NATIVE_EXIT\"\n").unwrap();
                fs::set_permissions(real, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let config = home.path().join("config.toml");
            let path = std::env::join_paths([&intercept, &upstream]).unwrap();
            Self {
                home,
                intercept,
                path,
                config,
            }
        }

        fn run(&self, name: &str, args: &[OsString], exit: i32) -> Output {
            let mut command = assert_cmd::Command::new(self.intercept.join(name));
            command
                .env_clear()
                .env("HOME", self.home.path())
                .env("PATH", &self.path)
                .env("DEV_CACHE_CONFIG", &self.config)
                .env("DEV_CACHE_MODE", "on")
                .env("NATIVE_EXIT", exit.to_string())
                .current_dir(self.home.path())
                .args(args)
                .timeout(Duration::from_secs(10));
            for name in ["WSL_DISTRO_NAME", "WSL_INTEROP", "COMPUTERNAME"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            command.assert().get_output().clone()
        }
    }

    fn assert_native(output: &Output, args: &[OsString], exit: i32) {
        let expected: Vec<u8> = args
            .iter()
            .flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
            .collect();
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        assert_eq!(output.stdout, expected);
        assert_eq!(output.stderr, b"unset\nunset\n");
    }

    fn completions() -> Vec<(&'static str, Vec<OsString>)> {
        [
            ("uv", vec!["generate-shell-completion", "bash"]),
            ("uv", vec!["--quiet", "generate-shell-completion", "zsh"]),
            (
                "uv",
                vec!["--offline", "generate-shell-completion", "invalid-shell"],
            ),
            (
                "uv",
                vec!["-vvn", "--color=never", "generate-shell-completion"],
            ),
            (
                "uv",
                vec![
                    "--directory",
                    "a path\nwith spaces",
                    "--config-file=odd;name.toml",
                    "generate-shell-completion",
                    "fish",
                ],
            ),
            ("uvx", vec!["--generate-shell-completion", "fish"]),
        ]
        .into_iter()
        .map(|(name, args)| (name, args.into_iter().map(OsString::from).collect()))
        .collect()
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, (SystemTime, Option<Vec<u8>>)> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .map(|entry| {
                let entry = entry.unwrap();
                let bytes = entry
                    .file_type()
                    .is_file()
                    .then(|| fs::read(entry.path()).unwrap());
                (
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    (entry.metadata().unwrap().modified().unwrap(), bytes),
                )
            })
            .collect()
    }

    #[test]
    fn completion_bypasses_invalid_configuration_without_creating_cache_state() {
        let fixture = Fixture::new();
        fs::write(&fixture.config, b"invalid TOML [").unwrap();
        let before = snapshot(fixture.home.path());
        for (name, args) in completions() {
            for exit in [0, 2, 23] {
                assert_native(&fixture.run(name, &args, exit), &args, exit);
            }
        }
        assert_eq!(snapshot(fixture.home.path()), before);
        for args in [
            vec!["--offline", "run", "generate-shell-completion"],
            vec!["--quiet", "tool", "run", "generate-shell-completion"],
            vec!["--quiet", "--", "generate-shell-completion"],
        ] {
            let args: Vec<_> = args.into_iter().map(OsString::from).collect();
            let output = fixture.run("uv", &args, 23);
            assert_eq!(output.status.code(), Some(10), "{output:?}");
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("TOML"));
        }
    }

    #[test]
    fn completion_bypasses_exclusive_maintenance_and_preserves_cache_state() {
        let fixture = Fixture::new();
        let root = RootHandle::initialize(&fixture.home.path().join("cache-root")).unwrap();
        let config = Config {
            root: Some(root.root.clone()),
            ..Config::default()
        };
        fs::write(&fixture.config, toml::to_string(&config).unwrap()).unwrap();
        let _exclusive = RootLease::exclusive(&root).unwrap();
        fs::write(
            root.control().join("last-automatic-gc.json"),
            b"not maintenance data",
        )
        .unwrap();
        let before = snapshot(&root.root);
        for (name, args) in completions() {
            for exit in [0, 2, 23] {
                assert_native(&fixture.run(name, &args, exit), &args, exit);
            }
        }
        assert_eq!(snapshot(&root.root), before);
        let args = vec![
            "--offline".into(),
            "run".into(),
            "generate-shell-completion".into(),
        ];
        let output = fixture.run("uv", &args, 23);
        assert_eq!(output.status.code(), Some(12), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("exclusive maintenance"));
    }
}
