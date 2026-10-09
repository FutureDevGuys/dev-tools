//! Retained Cargo outputs use public synthetic workspaces, never downstream code.
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use dev_cache::adapter::Adapter;
use dev_cache::config::Config;
use dev_cache::gc::{self, GcOverrides};
use dev_cache::provenance;
use dev_cache::resources::{self, CleanupStrategy, NativeTool, ResourceKind, ResourceRecord};
use dev_cache::root::RootHandle;

struct Fixture {
    temp: tempfile::TempDir,
    root: RootHandle,
    config: Config,
    config_path: PathBuf,
    checkout: PathBuf,
    first: PathBuf,
    second: PathBuf,
    intercepts: PathBuf,
    upstream: PathBuf,
    path: OsString,
}

impl Fixture {
    fn new(final_outputs: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("managed-root")).unwrap();
        let checkout = temp.path().join("synthetic-repository");
        let first = checkout.join("first-workspace");
        let second = checkout.join("second-workspace");
        let intercepts = temp.path().join("intercepts");
        let upstream = temp.path().join("native-tools");
        for directory in [
            checkout.join(".git/objects"),
            intercepts.clone(),
            upstream.clone(),
            temp.path().join("cargo-home"),
            temp.path().join("sysroot"),
            temp.path().join("other-sysroot"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(checkout.join(".git/HEAD"), "ref: refs/heads/synthetic\n").unwrap();
        for (workspace, name) in [(&first, "first_member"), (&second, "second_member")] {
            fs::create_dir_all(workspace.join("member/src")).unwrap();
            fs::write(
                workspace.join("Cargo.toml"),
                "[workspace]\nmembers = [\"member\"]\nresolver = \"2\"\n",
            )
            .unwrap();
            fs::write(
                workspace.join("member/Cargo.toml"),
                format!("[package]\nname = {name:?}\nversion = \"0.0.0\"\nedition = \"2021\"\n"),
            )
            .unwrap();
            fs::write(workspace.join("member/src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        }
        for name in ["cargo", "rustup", "dev-cache"] {
            symlink(env!("CARGO_BIN_EXE_dev-cache"), intercepts.join(name)).unwrap();
        }
        // Only locate-project reaches the native Cargo that built this test.
        // It resolves real manifest/workspace semantics without compiling,
        // fetching dependencies, or inventing a workspace from Git grouping.
        executable(
            &upstream.join("cargo"),
            r#"#!/bin/sh
set -eu
case "$*" in
  --version)
    case "${FIXTURE_CARGO_PROBE_MODE-}" in
      failed) printf 'private-capability-diagnostic\n' >&2; exit 42;;
      malformed) printf 'not a Cargo capability\n'; exit 0;;
    esac
    printf 'cargo %s (fixture)\n' "${FIXTURE_CARGO_VERSION-1.91.0}"
    exit 0;;
  '--version --verbose') printf 'cargo %s (fixture)\ncommit-hash: %s\n' "${FIXTURE_CARGO_VERSION-1.91.0}" "${FIXTURE_CARGO_COMMIT-cargo-a}"; exit 0;;
esac
if [ "${1-}" = locate-project ]; then
  test "$DEV_CACHE_MODE" = off
  test "$RUSTUP_AUTO_INSTALL" = 0
  printf '%s\000' "$PWD" "$@" > "$LOCATE_LOG"
  exec "$LOCATE_CARGO" "$@"
fi
printf 'CARGO_TARGET_DIR=%s\000CARGO_BUILD_TARGET_DIR=%s\000CARGO_BUILD_BUILD_DIR=%s\000DEV_CACHE_PROVENANCE=%s\000RUSTC_WRAPPER=%s\000PWD=%s\000' \
  "${CARGO_TARGET_DIR-}" "${CARGO_BUILD_TARGET_DIR-}" "${CARGO_BUILD_BUILD_DIR-}" "${DEV_CACHE_PROVENANCE-}" "${RUSTC_WRAPPER-}" "$PWD" > "$CAPTURE"
if [ -n "${NESTED_WORKSPACE-}" ]; then
  cd "$NESTED_WORKSPACE"
  CAPTURE="$NESTED_CAPTURE" NESTED_WORKSPACE= exec "$INTERCEPT_CARGO" build
fi
printf 'native stdout\n'
printf '%s\000' "$@"
printf 'native stderr\n' >&2
exit 23
"#,
        );
        executable(
            &upstream.join("rustc"),
            r#"#!/bin/sh
set -eu
test "$DEV_CACHE_MODE" = off
test "$RUSTUP_AUTO_INSTALL" = 0
case "${FIXTURE_RUSTC_MODE-}" in
  malformed) printf 'not a compiler identity\n'; exit 0;;
  oversized)
    i=0
    while [ "$i" -lt 2049 ]; do
      printf 'private-probe-payload-0123456789ab'
      i=$((i + 1))
    done
    exit 0;;
esac
case "$*" in
  '--version --verbose') printf 'rustc 1.91.0 (fixture)\ncommit-hash: %s\nhost: fixture-unknown-linux-gnu\n' "${FIXTURE_RUSTC_COMMIT-rustc-a}";;
  '--print sysroot') printf '%s\n' "$FIXTURE_SYSROOT";;
  *) exit 98;;
esac
"#,
        );
        executable(
            &upstream.join("rustup"),
            r#"#!/bin/sh
set -eu
test "$1" = run
FIXTURE_RUSTC_COMMIT="$2"
export FIXTURE_RUSTC_COMMIT
shift 2
program="$1"
shift
exec "$UPSTREAM/$program" "$@"
"#,
        );
        executable(&upstream.join("sccache"), "#!/bin/sh\nexit 0\n");
        let mut config = Config {
            root: Some(root.root.clone()),
            ..Config::default()
        };
        config.cargo.final_outputs = final_outputs;
        config.cargo.real_path = Some(upstream.join("cargo"));
        config.sccache.enabled = false;
        config.maintenance.automatic = false;
        config.gc.min_free_bytes = 0;
        config.gc.target_free_bytes = 0;
        let config_path = temp.path().join("config.toml");
        let path = std::env::join_paths([&intercepts, &upstream]).unwrap();
        let fixture = Self {
            temp,
            root,
            config,
            config_path,
            checkout,
            first,
            second,
            intercepts,
            upstream,
            path,
        };
        fixture.save_config();
        fixture
    }

    fn save_config(&self) {
        fs::write(&self.config_path, toml::to_string(&self.config).unwrap()).unwrap();
    }

    fn command(&self, name: &str, cwd: &Path) -> Command {
        let mut command = Command::new(self.intercepts.join(name));
        command
            .env_clear()
            .env("HOME", self.temp.path())
            .env("CARGO_HOME", self.temp.path().join("cargo-home"))
            .env("PATH", &self.path)
            .env("DEV_CACHE_CONFIG", &self.config_path)
            .env("CAPTURE", self.temp.path().join("capture"))
            .env("LOCATE_LOG", self.temp.path().join("locate-argv"))
            .env("LOCATE_CARGO", native_locator())
            .env("FIXTURE_SYSROOT", self.temp.path().join("sysroot"))
            .env("UPSTREAM", &self.upstream)
            .env("INTERCEPT_CARGO", self.intercepts.join("cargo"))
            .current_dir(cwd);
        for name in ["WSL_DISTRO_NAME", "WSL_INTEROP", "COMPUTERNAME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }

    fn build(&self, cwd: &Path, args: &[&str]) -> BTreeMap<String, String> {
        let mut command = self.command("cargo", cwd);
        command.args(args);
        native(command);
        self.capture("capture")
    }

    fn capture(&self, name: &str) -> BTreeMap<String, String> {
        fs::read(self.temp.path().join(name))
            .unwrap()
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let entry = std::str::from_utf8(entry).unwrap();
                let (name, value) = entry.split_once('=').unwrap();
                (name.to_owned(), value.to_owned())
            })
            .collect()
    }

    fn path_command(&self, workspace: &Path) -> Command {
        let mut command = self.command("dev-cache", &self.checkout);
        command
            .args(["--json", "path", "cargo", "--final-outputs", "--repo"])
            .arg(workspace);
        command
    }

    fn retained_path(&self, workspace: &Path) -> PathBuf {
        let output = run(self.path_command(workspace));
        assert_success(&output);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        PathBuf::from(value["path"].as_str().unwrap())
    }

    fn retained_record(&self) -> ResourceRecord {
        resources::list(&self.root)
            .unwrap()
            .into_iter()
            .find(|record| record.kind == ResourceKind::CargoFinalOutput)
            .unwrap()
    }
}

fn executable(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn native_locator() -> &'static Path {
    static CARGO: OnceLock<PathBuf> = OnceLock::new();
    CARGO.get_or_init(|| {
        let cargo = PathBuf::from(env!("CARGO"));
        let rustup = cargo.with_file_name("rustup");
        let cargo = if same_file::is_same_file(&cargo, &rustup).unwrap_or(false) {
            // The test may have been built through a Rustup proxy. Resolve its
            // already-installed Cargo before entering the isolated fake home.
            let mut command = Command::new(rustup);
            command
                .args(["which", "cargo"])
                .env("RUSTUP_AUTO_INSTALL", "0")
                .env("DEV_CACHE_MODE", "off");
            let output = dev_tools_command::run_prepared_bounded_command(
                &mut command,
                Duration::from_secs(10),
                64 * 1024,
            )
            .unwrap();
            assert!(output.status.success(), "resolve installed fixture Cargo");
            PathBuf::from(std::str::from_utf8(&output.stdout).unwrap().trim())
        } else {
            cargo
        };
        cargo.canonicalize().unwrap()
    })
}

fn run(command: Command) -> Output {
    assert_cmd::Command::from_std(command)
        .timeout(Duration::from_secs(20))
        .output()
        .unwrap()
}

fn native(command: Command) -> Output {
    let output = run(command);
    assert_eq!(
        output.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (SystemTime, Option<Vec<u8>>)> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path().strip_prefix(root).unwrap().to_path_buf();
            let modified = entry.metadata().unwrap().modified().unwrap();
            let bytes = entry
                .file_type()
                .is_file()
                .then(|| fs::read(entry.path()).unwrap());
            (path, (modified, bytes))
        })
        .collect()
}

#[test]
fn omitted_opt_in_preserves_configuration_and_intermediate_only_routing() {
    let defaults = Config::default();
    assert!(!defaults.cargo.final_outputs);
    assert!(!toml::to_string(&defaults)
        .unwrap()
        .contains("final_outputs"));
    let legacy = Config::parse("version = 2\nenabled = false\n[cargo]\nenabled = true\n").unwrap();
    assert!(!legacy.cargo.final_outputs);
    let fixture = Fixture::new(false);
    let environment = fixture.build(&fixture.first, &["build"]);
    assert!(environment["CARGO_TARGET_DIR"].is_empty());
    assert!(environment["CARGO_BUILD_BUILD_DIR"].ends_with("/{workspace-path-hash}"));
    assert!(!fixture.root.platform_root.join("outputs").exists());
    assert!(!fixture.temp.path().join("locate-argv").exists());
    assert!(resources::list(&fixture.root)
        .unwrap()
        .iter()
        .all(|record| record.kind != ResourceKind::CargoFinalOutput));
    assert!(!run(fixture.path_command(&fixture.first)).status.success());

    let fixture = Fixture::new(true);
    let mut command = fixture.command("cargo", &fixture.first);
    command
        .args(["build"])
        .env("FIXTURE_CARGO_VERSION", "1.90.0");
    native(command);
    let environment = fixture.capture("capture");
    assert!(environment["CARGO_TARGET_DIR"].is_empty());
    assert!(environment["CARGO_BUILD_BUILD_DIR"].is_empty());
    assert!(resources::list(&fixture.root).unwrap().is_empty());
    assert!(!fixture.temp.path().join("locate-argv").exists());
}

#[test]
fn native_workspace_root_member_and_manifest_selection_share_only_the_right_outputs() {
    let fixture = Fixture::new(true);
    let root = fixture.build(&fixture.first, &["build"]);
    let member = fixture.build(&fixture.first.join("member/src"), &["check"]);
    let manifest = fixture.build(
        &fixture.checkout,
        &[
            "build",
            "--manifest-path",
            "first-workspace/member/Cargo.toml",
        ],
    );
    let second = fixture.build(
        &fixture.checkout,
        &[
            "build",
            "--manifest-path=second-workspace/member/Cargo.toml",
        ],
    );
    assert_eq!(root["CARGO_TARGET_DIR"], member["CARGO_TARGET_DIR"]);
    assert_eq!(root["CARGO_TARGET_DIR"], manifest["CARGO_TARGET_DIR"]);
    assert_ne!(root["CARGO_TARGET_DIR"], second["CARGO_TARGET_DIR"]);
    assert_eq!(
        root["CARGO_BUILD_BUILD_DIR"],
        second["CARGO_BUILD_BUILD_DIR"]
    );
    let target = Path::new(&root["CARGO_TARGET_DIR"]);
    let relative = target
        .strip_prefix(fixture.root.platform_root.join("outputs/cargo"))
        .unwrap();
    let components: Vec<_> = relative.iter().collect();
    assert_eq!(components.len(), 2);
    for digest in components {
        let digest = digest.to_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert!(!root["CARGO_TARGET_DIR"].contains('{'));
    assert_eq!(fixture.retained_path(&fixture.first), target);
    assert!(!fixture.first.join("target").exists());
    assert!(!fixture.first.join("Cargo.lock").exists());
    assert!(fs::read(fixture.temp.path().join("locate-argv"))
        .unwrap()
        .split(|byte| *byte == 0)
        .any(|arg| arg == b"--workspace"));
}

#[test]
fn compiler_cargo_and_sysroot_identities_partition_only_the_toolchain_component() {
    let fixture = Fixture::new(true);
    let original = fixture.retained_path(&fixture.first);
    for (variable, value) in [
        ("FIXTURE_RUSTC_COMMIT", OsString::from("rustc-b")),
        ("FIXTURE_CARGO_COMMIT", OsString::from("cargo-b")),
        (
            "FIXTURE_SYSROOT",
            fixture.temp.path().join("other-sysroot").into_os_string(),
        ),
    ] {
        let mut command = fixture.path_command(&fixture.first);
        command.env(variable, value);
        let output = run(command);
        assert_success(&output);
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let changed = Path::new(result["path"].as_str().unwrap());
        assert_eq!(original.parent(), changed.parent(), "{variable}");
        assert_ne!(original, changed, "{variable}");
    }
    assert_eq!(original, fixture.retained_path(&fixture.first));
}

#[test]
fn explicit_cli_and_environment_layouts_preserve_native_arguments_and_streams() {
    for args in [
        vec!["build", "--target-dir", "chosen output"],
        vec!["build", "--target-dir=chosen output"],
        vec!["build", "--config", "build.target-dir='chosen output'"],
        vec!["build", "--config=build.target-dir='chosen output'"],
        vec!["build", "--build-dir", "chosen intermediate"],
    ] {
        let fixture = Fixture::new(true);
        let mut direct = fixture.command("cargo", &fixture.first);
        direct = replace_program(direct, &fixture.upstream.join("cargo"));
        direct.args(&args);
        let expected = native(direct);
        let expected_environment = fixture.capture("capture");
        let mut intercepted = fixture.command("cargo", &fixture.first);
        intercepted.args(&args);
        let actual = native(intercepted);
        assert_eq!(actual.stdout, expected.stdout);
        // Eligibility abstention is an allowed diagnostic; native stderr survives.
        assert!(actual.stderr.ends_with(&expected.stderr));
        assert_eq!(fixture.capture("capture"), expected_environment);
        assert!(resources::list(&fixture.root).unwrap().is_empty());
    }
    for variable in [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
    ] {
        let fixture = Fixture::new(true);
        let mut command = fixture.command("cargo", &fixture.first);
        command.arg("build").env(variable, "relative chosen output");
        native(command);
        let environment = fixture.capture("capture");
        assert_eq!(environment[variable], "relative chosen output");
        for other in [
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET_DIR",
            "CARGO_BUILD_BUILD_DIR",
        ] {
            if other != variable {
                assert!(environment[other].is_empty());
            }
        }
        assert!(resources::list(&fixture.root).unwrap().is_empty());
    }
}

#[test]
fn native_profile_target_triple_and_application_arguments_are_forwarded_unchanged() {
    let fixture = Fixture::new(true);
    let expected_target = fixture.retained_path(&fixture.first);
    for args in [
        vec![
            "build",
            "--profile",
            "release",
            "--target",
            "aarch64-unknown-linux-gnu",
        ],
        vec![
            "test",
            "--no-run",
            "--profile=custom",
            "--target=x86_64-unknown-linux-gnu",
        ],
        vec![
            "run",
            "--release",
            "--",
            "--target-dir",
            "application argument",
        ],
    ] {
        let mut direct = replace_program(
            fixture.command("cargo", &fixture.first),
            &fixture.upstream.join("cargo"),
        );
        direct.args(&args);
        let expected = native(direct);
        let mut command = fixture.command("cargo", &fixture.first);
        command.args(&args);
        let actual = native(command);
        assert_eq!(actual.stdout, expected.stdout);
        assert_eq!(actual.stderr, expected.stderr);
        assert_eq!(
            Path::new(&fixture.capture("capture")["CARGO_TARGET_DIR"]),
            expected_target
        );
    }
}

fn replace_program(command: Command, program: &Path) -> Command {
    let mut direct = Command::new(program);
    direct.env_clear();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            direct.env(name, value);
        }
    }
    direct.current_dir(command.get_current_dir().unwrap());
    direct
}

#[test]
fn persistent_configuration_is_read_from_invocation_cwd_not_manifest_directory() {
    let fixture = Fixture::new(true);
    let caller = fixture.temp.path().join("caller");
    fs::create_dir_all(caller.join(".cargo")).unwrap();
    let config_path = caller.join(".cargo/config.toml");
    fs::write(&config_path, "[build]\ntarget-dir = 'caller-owned'\n").unwrap();
    let mut command = fixture.command("cargo", &caller);
    command
        .args(["build", "--manifest-path"])
        .arg(fixture.first.join("Cargo.toml"));
    native(command);
    assert!(fixture.capture("capture")["CARGO_TARGET_DIR"].is_empty());
    assert!(resources::list(&fixture.root).unwrap().is_empty());
    assert!(!fixture.temp.path().join("locate-argv").exists());
    fs::remove_file(config_path).unwrap();
    fs::create_dir(fixture.first.join(".cargo")).unwrap();
    fs::write(
        fixture.first.join(".cargo/config.toml"),
        "[build]\ntarget-dir = 'manifest-local'\n",
    )
    .unwrap();
    let mut command = fixture.command("cargo", &caller);
    command
        .args(["build", "--manifest-path"])
        .arg(fixture.first.join("Cargo.toml"));
    native(command);
    assert!(!fixture.capture("capture")["CARGO_TARGET_DIR"].is_empty());
    let from_workspace = fixture.build(&fixture.first, &["build"]);
    assert!(from_workspace["CARGO_TARGET_DIR"].is_empty());
}

#[test]
fn indirect_compiler_configuration_and_user_aliases_abstain_before_probes() {
    for configuration in [
        "[build]\nrustc = 'different-rustc'\n",
        "[build]\nrustc-wrapper = 'different-wrapper'\n",
        "[env]\nRUSTC = 'different-rustc'\n",
        "include = 'other-config.toml'\n",
    ] {
        let fixture = Fixture::new(true);
        fs::create_dir(fixture.first.join(".cargo")).unwrap();
        fs::write(fixture.first.join(".cargo/config.toml"), configuration).unwrap();
        let environment = fixture.build(&fixture.first, &["build"]);
        assert!(environment["CARGO_TARGET_DIR"].is_empty());
        assert!(resources::list(&fixture.root).unwrap().is_empty());
        assert!(!fixture.temp.path().join("locate-argv").exists());
    }
    for command in ["b", "c", "t", "r", "d", "custom-build"] {
        let fixture = Fixture::new(true);
        assert!(fixture.build(&fixture.first, &[command])["CARGO_TARGET_DIR"].is_empty());
        assert!(resources::list(&fixture.root).unwrap().is_empty());
    }
}

#[test]
fn fifo_and_oversized_cargo_configuration_abstain_without_blocking_or_probing() {
    for kind in ["fifo", "oversized"] {
        let fixture = Fixture::new(true);
        fs::create_dir(fixture.first.join(".cargo")).unwrap();
        let configuration = fixture.first.join(".cargo/config.toml");
        if kind == "fifo" {
            let mut command = Command::new("mkfifo");
            command.arg(&configuration);
            assert_success(&run(command));
        } else {
            // Valid comment-only TOML exceeds the reader's 1 MiB bound.
            fs::write(&configuration, format!("#{}\n", "x".repeat(1024 * 1024))).unwrap();
        }
        let mut command = assert_cmd::Command::from_std(fixture.command("cargo", &fixture.first));
        let output = command
            .arg("build")
            .timeout(Duration::from_secs(5))
            .assert()
            .code(23)
            .get_output()
            .clone();
        assert!(output.stdout.starts_with(b"native stdout\n"));
        assert!(fixture.capture("capture")["CARGO_TARGET_DIR"].is_empty());
        assert!(!fixture.temp.path().join("locate-argv").exists());
        assert!(resources::list(&fixture.root).unwrap().is_empty());
    }
}

#[test]
fn nested_managed_cargo_rebinds_workspace_and_keeps_provenance_flat() {
    let mut fixture = Fixture::new(true);
    fixture.config.sccache.enabled = true;
    fixture.save_config();
    let expected_outer = fixture.retained_path(&fixture.first);
    let expected_inner = fixture.retained_path(&fixture.second);
    let mut command = fixture.command("cargo", &fixture.first);
    command
        .arg("build")
        .env("NESTED_WORKSPACE", &fixture.second)
        .env("NESTED_CAPTURE", fixture.temp.path().join("nested-capture"));
    native(command);
    let outer = fixture.capture("capture");
    let inner = fixture.capture("nested-capture");
    assert_eq!(Path::new(&outer["CARGO_TARGET_DIR"]), expected_outer);
    assert_eq!(Path::new(&inner["CARGO_TARGET_DIR"]), expected_inner);
    assert_eq!(inner["RUSTC_WRAPPER"], "sccache");
    for environment in [&outer, &inner] {
        let provenance: serde_json::Value =
            serde_json::from_str(&environment[provenance::ENV_NAME]).unwrap();
        assert_eq!(
            provenance["variables"]["CARGO_TARGET_DIR"]["value"],
            environment["CARGO_TARGET_DIR"]
        );
        assert!(provenance["variables"].get(provenance::ENV_NAME).is_none());
    }
    let mut command = fixture.command("cargo", &fixture.second);
    command
        .arg("build")
        .env(provenance::ENV_NAME, &outer[provenance::ENV_NAME])
        .env("CARGO_TARGET_DIR", "user-replaced-target");
    native(command);
    assert_eq!(
        fixture.capture("capture")["CARGO_TARGET_DIR"],
        "user-replaced-target"
    );
}

#[test]
fn nested_abstention_or_user_override_drops_inherited_managed_output_layout() {
    for scenario in [
        "cli",
        "environment",
        "alias",
        "configuration",
        "old-cargo",
        "compiler",
    ] {
        let fixture = Fixture::new(true);
        let outer = fixture.build(&fixture.first, &["build"]);
        let mut command = fixture.command("cargo", &fixture.second);
        for name in [
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_BUILD_DIR",
            provenance::ENV_NAME,
        ] {
            command.env(name, &outer[name]);
        }
        match scenario {
            "cli" => {
                command.args(["build", "--target-dir", "chosen-target"]);
            }
            "environment" => {
                command
                    .arg("build")
                    .env("CARGO_BUILD_TARGET_DIR", "chosen-target");
            }
            "alias" => {
                command.arg("b");
            }
            "configuration" => {
                fs::create_dir(fixture.second.join(".cargo")).unwrap();
                fs::write(
                    fixture.second.join(".cargo/config.toml"),
                    "[build]\ntarget-dir = 'chosen-target'\n",
                )
                .unwrap();
                command.arg("build");
            }
            "old-cargo" => {
                command.arg("build").env("FIXTURE_CARGO_VERSION", "1.90.0");
            }
            "compiler" => {
                command.arg("build").env("RUSTC", "user-selected-rustc");
            }
            _ => unreachable!(),
        }
        native(command);
        let inner = fixture.capture("capture");
        assert!(inner["CARGO_TARGET_DIR"].is_empty(), "{scenario}");
        assert!(inner["CARGO_BUILD_BUILD_DIR"].is_empty(), "{scenario}");
        if scenario == "environment" {
            assert_eq!(inner["CARGO_BUILD_TARGET_DIR"], "chosen-target");
        }
    }
}

#[test]
fn explicit_exec_and_rustup_cargo_use_the_selected_native_identity() {
    let fixture = Fixture::new(true);
    let expected = fixture.retained_path(&fixture.first);
    let mut command = fixture.command("dev-cache", &fixture.first);
    command.args(["exec", "cargo", "--", "cargo", "build"]);
    native(command);
    assert_eq!(
        Path::new(&fixture.capture("capture")["CARGO_TARGET_DIR"]),
        expected
    );
    let mut targets = Vec::new();
    for toolchain in ["fixture-toolchain-a", "fixture-toolchain-b"] {
        let mut command = fixture.command("rustup", &fixture.first);
        command.args(["run", toolchain, "cargo", "build"]);
        native(command);
        targets.push(PathBuf::from(
            &fixture.capture("capture")["CARGO_TARGET_DIR"],
        ));
    }
    assert_eq!(targets[0].parent(), expected.parent());
    assert_eq!(targets[0].parent(), targets[1].parent());
    assert_ne!(targets[0], targets[1]);
}

#[test]
fn stale_orphaned_and_pressure_gc_preserve_retained_outputs() {
    for scenario in ["stale", "orphan", "pressure"] {
        let fixture = Fixture::new(true);
        let environment = fixture.build(&fixture.first, &["build"]);
        let target = Path::new(&environment["CARGO_TARGET_DIR"]);
        fs::write(target.join("final-binary"), b"retained executable bytes").unwrap();
        let intermediate = Path::new(&environment["CARGO_BUILD_BUILD_DIR"])
            .parent()
            .unwrap();
        fs::write(intermediate.join("disposable-object"), b"disposable bytes").unwrap();
        let record = fixture.retained_record();
        assert_eq!(record.cleanup, CleanupStrategy::Retain);
        let catalog = resources::catalog_path(&fixture.root, &record.resource_id);
        let before = fs::read(&catalog).unwrap();
        let mut policy = fixture.config.gc.clone();
        policy.stale_after_days = if scenario == "pressure" { u64::MAX } else { 0 };
        policy.orphan_grace_days = 0;
        policy.pressure_min_age_hours = 0;
        if scenario == "orphan" {
            fs::remove_dir_all(&fixture.checkout).unwrap();
        }
        if scenario == "pressure" {
            policy.max_bytes = Some(0);
        }
        for apply in [false, true] {
            let report =
                gc::collect(&fixture.root, &policy, 120, &GcOverrides::default(), apply).unwrap();
            assert!(
                report.failures.is_empty(),
                "{scenario}: {:?}",
                report.failures
            );
            assert!(report
                .actions
                .iter()
                .any(|action| action.reason == scenario));
            assert!(report.actions.iter().all(|action| {
                !target.starts_with(&action.path) && !action.path.starts_with(target)
            }));
            assert!(report.abstentions.iter().any(|item| {
                item.resource_id.as_deref() == Some(record.resource_id.as_str())
                    && item.reason.contains("retained")
            }));
            assert_eq!(
                fs::read(target.join("final-binary")).unwrap(),
                b"retained executable bytes"
            );
            assert_eq!(fs::read(&catalog).unwrap(), before);
            if scenario == "pressure" {
                assert!(report.size_limit_shortfall_bytes >= 25);
            }
        }
        assert!(!intermediate.join("disposable-object").exists());
    }
}

#[test]
fn tampered_catalog_cannot_turn_retained_outputs_into_disposable_cache() {
    for tamper in ["cleanup", "adapter", "kind"] {
        let fixture = Fixture::new(true);
        let environment = fixture.build(&fixture.first, &["build"]);
        let target = Path::new(&environment["CARGO_TARGET_DIR"]);
        fs::write(target.join("final-binary"), b"keep this output").unwrap();
        let mut record = fixture.retained_record();
        let old_catalog = resources::catalog_path(&fixture.root, &record.resource_id);
        match tamper {
            "cleanup" => record.cleanup = CleanupStrategy::OwnedDirectory,
            "adapter" => record.adapter = Adapter::Npm,
            "kind" => {
                record.kind = ResourceKind::CargoIntermediate;
                record.cleanup = CleanupStrategy::OwnedDirectory;
                // Recompute the documented identifier so containment, rather
                // than a trivial identifier mismatch, must reject this record.
                record.resource_id = blake3::hash(
                    format!("v1\0{:?}\0{}", record.kind, record.relative_path.display()).as_bytes(),
                )
                .to_hex()
                .to_string();
            }
            _ => unreachable!(),
        }
        fs::remove_file(old_catalog).unwrap();
        let catalog = resources::catalog_path(&fixture.root, &record.resource_id);
        let bytes = serde_json::to_vec(&record).unwrap();
        fs::write(&catalog, &bytes).unwrap();
        let (_, issues) = resources::scan(&fixture.root).unwrap();
        assert_eq!(issues.len(), 1);
        let report = gc::collect(
            &fixture.root,
            &fixture.config.gc,
            0,
            &GcOverrides {
                max_bytes: Some(0),
                stale_after_days: Some(0),
                ..GcOverrides::default()
            },
            true,
        )
        .unwrap();
        assert!(report.abstentions.iter().any(|item| item.path == catalog));
        assert_eq!(
            fs::read(target.join("final-binary")).unwrap(),
            b"keep this output"
        );
        assert_eq!(fs::read(catalog).unwrap(), bytes);
    }
}

#[test]
fn unregistered_nonempty_or_linked_output_storage_is_not_adopted() {
    for linked in [false, true] {
        let fixture = Fixture::new(true);
        let target = fixture.retained_path(&fixture.first);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let payload = if linked {
            let outside = fixture.temp.path().join("unmanaged-output");
            fs::create_dir(&outside).unwrap();
            symlink(&outside, &target).unwrap();
            outside.join("final-binary")
        } else {
            fs::create_dir(&target).unwrap();
            target.join("final-binary")
        };
        fs::write(&payload, b"not adoption authority").unwrap();
        let error = resources::register_routed(
            &fixture.root,
            Adapter::Cargo,
            &HashMap::from([(
                "CARGO_TARGET_DIR".to_owned(),
                target.to_str().unwrap().to_owned(),
            )]),
            &NativeTool::default(),
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(!format!("{error:#}").is_empty());
        assert!(resources::list(&fixture.root).unwrap().is_empty());
        assert_eq!(fs::read(payload).unwrap(), b"not adoption authority");
    }
}

#[test]
fn path_and_report_are_read_only_and_retained_bytes_are_an_other_bytes_subset() {
    let fixture = Fixture::new(true);
    let before = snapshot(&fixture.root.root);
    let target = fixture.retained_path(&fixture.first);
    assert_eq!(snapshot(&fixture.root.root), before);
    assert!(!target.exists());
    let environment = fixture.build(&fixture.first, &["build"]);
    assert_eq!(target, Path::new(&environment["CARGO_TARGET_DIR"]));
    fs::write(target.join("final-binary"), [7_u8; 137]).unwrap();
    fs::write(fixture.root.shared().join("ordinary-cache"), [8_u8; 29]).unwrap();
    let before = snapshot(&fixture.root.root);
    let mut command = fixture.command("dev-cache", &fixture.checkout);
    command.args(["--json", "report"]);
    let output = run(command);
    assert_success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["complete"], true);
    assert_eq!(report["retained_outputs_bytes"], 137);
    assert!(report["other_bytes"].as_u64().unwrap() >= 137);
    let old_categories: u64 = [
        "repos_bytes",
        "shared_bytes",
        "artifacts_bytes",
        "other_bytes",
    ]
    .iter()
    .map(|name| report[*name].as_u64().unwrap())
    .sum();
    assert_eq!(report["bytes"].as_u64().unwrap(), old_categories);
    assert_eq!(fixture.retained_path(&fixture.first), target);
    assert_eq!(snapshot(&fixture.root.root), before);
}

#[test]
fn bounded_identity_probe_failures_do_not_leak_stdout_or_launch_native_work() {
    for mode in ["malformed", "oversized"] {
        let fixture = Fixture::new(true);
        let before = snapshot(&fixture.root.root);
        let mut command = fixture.path_command(&fixture.first);
        command.env("FIXTURE_RUSTC_MODE", mode);
        let output = run(command);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-probe-payload"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-probe-payload"));
        assert!(output.stdout.len() < 4096);
        assert!(output.stderr.len() < 4096);
        assert!(!fixture.temp.path().join("capture").exists());
        assert_eq!(snapshot(&fixture.root.root), before);
    }
}

#[test]
fn failed_or_malformed_capability_is_not_treated_as_proven_old_cargo() {
    for mode in ["failed", "malformed"] {
        let fixture = Fixture::new(true);
        let before = snapshot(&fixture.root.root);
        let mut command = fixture.command("cargo", &fixture.first);
        command.arg("build").env("FIXTURE_CARGO_PROBE_MODE", mode);
        let output = run(command);
        assert!(!output.status.success());
        assert!(!fixture.temp.path().join("capture").exists());
        assert!(!fixture.temp.path().join("locate-argv").exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-capability-diagnostic"));
        assert_eq!(snapshot(&fixture.root.root), before);
    }
}
