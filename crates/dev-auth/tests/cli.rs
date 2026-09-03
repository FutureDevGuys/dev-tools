#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use wait_timeout::ChildExt;

const PUBLIC_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const PUBLIC_SUBPROCESS_OUTPUT_LIMIT: u64 = 1024 * 1024;

fn bounded_reader<T>(mut reader: T) -> thread::JoinHandle<Vec<u8>>
where
    T: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut output = Vec::new();
        reader
            .by_ref()
            .take(PUBLIC_SUBPROCESS_OUTPUT_LIMIT + 1)
            .read_to_end(&mut output)
            .unwrap();
        output
    })
}

fn bounded_output(command: &mut Command) -> Output {
    bounded_output_with_timeout(
        command,
        PUBLIC_SUBPROCESS_TIMEOUT,
        "public dev-auth subprocess",
    )
}

fn bounded_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
    description: &str,
) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = bounded_reader(child.stdout.take().unwrap());
    let stderr = bounded_reader(child.stderr.take().unwrap());
    let (status, timed_out) = match child.wait_timeout(timeout).unwrap() {
        Some(status) => (status, false),
        None => {
            child.kill().unwrap();
            (child.wait().unwrap(), true)
        }
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    if timed_out {
        panic!(
            "{description} exceeded its {} second bound: stdout={} stderr={}",
            timeout.as_secs(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }
    assert!(stdout.len() <= PUBLIC_SUBPROCESS_OUTPUT_LIMIT as usize);
    assert!(stderr.len() <= PUBLIC_SUBPROCESS_OUTPUT_LIMIT as usize);
    Output {
        status,
        stdout,
        stderr,
    }
}

fn private_runtime() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn private_program_root() -> TempDir {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let directory = tempfile::Builder::new()
        .prefix("dev-auth-cli-programs-")
        .tempdir_in(user.dir)
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn standalone_binary_embeds_every_setup_source_template() {
    for name in [
        "deployment",
        "administrator-policy",
        "user-only-policy",
        "user-config",
    ] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .args(["setup", "template", name])
                .env_clear(),
        );
        assert!(output.status.success(), "{name}: {:?}", output);
        assert!(output.stderr.is_empty(), "{name}");
        match name {
            "deployment" => {
                dev_auth::deployment::parse_deployment_document(&output.stdout).unwrap();
            }
            "administrator-policy" | "user-only-policy" => {
                dev_auth::policy_v2::parse_system_policy_v2(&output.stdout).unwrap();
            }
            "user-config" => {
                dev_auth::policy_v2::parse_user_config_v2(&output.stdout).unwrap();
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn full_setup_apply_never_falls_back_to_a_binary_only_v2_plan() {
    let root = private_runtime();
    let plan = root.path().join("setup-plan.json");
    fs::write(
        &plan,
        br#"{"schema":"dev-auth-setup-plan-v2","actions":[]}"#,
    )
    .unwrap();
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();

    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "setup",
                "apply",
                "--plan",
                plan.to_str().unwrap(),
                "--sha256",
                &"0".repeat(64),
                "--format",
                "json",
            ])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("accepts only a full setup plan v3"));
}

#[test]
fn setup_v3_does_not_expose_a_global_launcher_activation_command() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["setup", "activate", "--mode", "user-only"])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("unknown setup operation"));
}

#[test]
fn typed_reconcile_cli_reserves_only_the_fixed_protocol_grammar() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "reconcile",
                "plan",
                "--source",
                "relative.toml",
                "--output",
                "/tmp/plan.json",
                "--format",
                "json",
            ])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("source and output paths must be absolute"));
    assert!(!error.contains("unknown command"));
}

#[test]
fn typed_reconcile_defers_when_standalone_system_is_absent() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("config-v2.toml");
    let plan = root.path().join("plan.json");
    fs::write(&source, b"version = 2\n").unwrap();
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "reconcile",
                "plan",
                "--source",
                source.to_str().unwrap(),
                "--output",
                plan.to_str().unwrap(),
                "--format",
                "json",
            ])
            .env_clear(),
    );

    assert!(output.status.success(), "{:?}", output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["deferred"], true);
    assert_eq!(report["next_action"], "setup");
    assert_eq!(report["diagnostics"][0], "system_installation_absent");
    assert!(!plan.exists());
}

#[test]
fn release_manifest_signing_rejects_an_empty_payload_before_broker_access() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["sign-release-manifest", "--profile", "release"])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("release manifest must not be empty"),
        "{error}"
    );
    assert!(!error.contains("unknown command"), "{error}");
}

#[cfg(target_os = "linux")]
struct NativeUserSandbox {
    _root: TempDir,
    root: PathBuf,
    home: PathBuf,
    runtime: PathBuf,
    passwd: PathBuf,
}

#[cfg(target_os = "linux")]
impl NativeUserSandbox {
    fn new() -> Self {
        assert!(Path::new("/usr/bin/bwrap").is_file());
        let root = private_program_root();
        let root_path = root.path().to_path_buf();
        let home = root_path.join("native-home");
        let runtime = root_path.join("run-user");
        let passwd = root_path.join("passwd");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&root_path).unwrap();
        fs::write(
            &passwd,
            format!(
                "dev-auth-test:x:{}:{}::{}:/bin/sh\n",
                metadata.uid(),
                metadata.gid(),
                home.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&passwd, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            _root: root,
            root: root_path,
            home,
            runtime,
            passwd,
        }
    }

    fn command(&self, program: &Path, cwd: &Path) -> Command {
        let uid = fs::metadata(&self.root).unwrap().uid();
        let program_name = program.file_name().unwrap();
        let sandbox_program = Path::new("/test-bin").join(program_name);
        let attacker_home = self.root.join("attacker-home");
        let attacker_config = self.root.join("attacker-config");
        fs::create_dir_all(&attacker_home).unwrap();
        fs::create_dir_all(&attacker_config).unwrap();
        let mut command = Command::new("/usr/bin/bwrap");
        command
            .arg("--die-with-parent")
            .args(["--tmpfs", "/"])
            .args(["--dir", "/usr"])
            .args(["--ro-bind", "/usr", "/usr"])
            .args(["--symlink", "usr/bin", "/bin"])
            .args(["--symlink", "usr/lib", "/lib"])
            .args(["--symlink", "usr/lib", "/lib64"])
            .args(["--dir", "/storage"])
            .args(["--ro-bind", "/storage", "/storage"])
            .args(["--dev", "/dev"])
            .args(["--proc", "/proc"])
            .args(["--dir", "/etc"])
            .args(["--dir", "/run"])
            .args(["--dir", "/run/user"])
            .args(["--dir", "/tmp"])
            .args(["--dir", "/test-bin"])
            .arg("--ro-bind")
            .arg(program)
            .arg(&sandbox_program);
        let mut ancestor = PathBuf::new();
        for component in self
            .root
            .components()
            .take(self.root.components().count() - 1)
        {
            ancestor.push(component.as_os_str());
            if ancestor != Path::new("/") {
                command.arg("--dir").arg(&ancestor);
            }
        }
        command
            .arg("--bind")
            .arg(&self.root)
            .arg(&self.root)
            .arg("--bind")
            .arg(&self.passwd)
            .arg("/etc/passwd")
            .arg("--bind")
            .arg(&self.runtime)
            .arg(format!("/run/user/{uid}"))
            .arg("--clearenv")
            .arg("--setenv")
            .arg("HOME")
            .arg(&attacker_home)
            .arg("--setenv")
            .arg("XDG_CONFIG_HOME")
            .arg(&attacker_config)
            .arg("--setenv")
            .arg("PATH")
            .arg("/usr/bin")
            .arg("--chdir")
            .arg(cwd)
            .arg("--")
            .arg(sandbox_program);
        command
    }

    fn install_binary(&self, destination: &Path) {
        fs::copy(env!("CARGO_BIN_EXE_dev-auth"), destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[cfg(target_os = "linux")]
fn run_standalone_user_only_setup_child() {
    use dev_auth::deployment::{
        normalize_deployment, parse_deployment_document, DeploymentCliInput,
    };
    use dev_auth::setup::{build_plan, rollback_at, InstallMode, InstallRequest, SetupPaths};
    use dev_auth::setup_v3::{apply_setup_plan_v3, build_setup_plan_v3_at, render_setup_plan_v3};

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let root = tempfile::Builder::new()
        .prefix("dev-auth-clean-home-")
        .tempdir_in(&user.dir)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let candidate = user.dir.parent().unwrap().join("product");

    let upstream_log = root.path().join("native-git.log");
    let native_git = root.path().join("native-git");
    fs::write(
        &native_git,
        format!(
            "#!/bin/sh\nprintf 'editor=%s\\n' \"${{GIT_EDITOR-}}\" > '{}'\nprintf 'arg=%s\\n' \"$@\" >> '{}'\nexit 23\n",
            upstream_log.display(),
            upstream_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&native_git, fs::Permissions::from_mode(0o700)).unwrap();
    let native_gh = root.path().join("native-gh");
    let op = root.path().join("op");
    let ssh = root.path().join("ssh");
    let ssh_keygen = root.path().join("ssh-keygen");
    for path in [&native_gh, &op, &ssh, &ssh_keygen] {
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let policy = root.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"
[trusted_launchers]
[github_apps]
[credential_slots]
[authority_caps]
[workspace_caps]
"#,
            user.name,
            op.display(),
            native_git.display(),
            native_gh.display(),
            ssh.display(),
            ssh_keygen.display()
        ),
    )
    .unwrap();
    let config = root.path().join("config.toml");
    fs::write(&config, b"version = 2\n").unwrap();
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let deployment = parse_deployment_document(
        format!(
            r#"schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "transparent"
administrator_policy = "{}"

[[users]]
name = "{}"
config = "{}"
"#,
            policy.display(),
            user.name,
            config.display()
        )
        .as_bytes(),
    )
    .unwrap();
    let intent = normalize_deployment(Some(deployment), DeploymentCliInput::default()).unwrap();
    let paths = SetupPaths::user_only(&user.dir);
    let installation = build_plan(
        &paths,
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.3.0-clean-device-test".into(),
            source_executable: candidate,
            native_git,
            native_gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    let plan = build_setup_plan_v3_at(intent, installation, false).unwrap();
    let (_, digest) = render_setup_plan_v3(&plan).unwrap();
    let first = apply_setup_plan_v3(&plan, &digest, &std::collections::BTreeMap::new()).unwrap();
    assert!(first.changed);
    assert!(first.verified);

    let second = apply_setup_plan_v3(&plan, &digest, &std::collections::BTreeMap::new()).unwrap();
    assert!(!second.changed);
    assert!(second.verified);

    let installation_lock = paths.data_root.join("installation.lock");
    fs::set_permissions(&installation_lock, fs::Permissions::from_mode(0o000)).unwrap();
    for arguments in [&["status", "--broker"][..], &["explain", "git"][..]] {
        let output = Command::new(user.dir.join(".local/bin/dev-auth"))
            .args(arguments)
            .env_clear()
            .env("HOME", &user.dir)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let reconcile_plan = root.path().join("reconcile-plan.json");
    let reconcile = Command::new(user.dir.join(".local/bin/dev-auth"))
        .args([
            "reconcile",
            "plan",
            "--source",
            config.to_str().unwrap(),
            "--output",
            reconcile_plan.to_str().unwrap(),
            "--format",
            "json",
        ])
        .env_clear()
        .env("HOME", &user.dir)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        reconcile.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&reconcile.stdout),
        String::from_utf8_lossy(&reconcile.stderr)
    );
    fs::remove_file(reconcile_plan).unwrap();

    let unresolved_workload = user.dir.join(".local/bin/future-agent");
    symlink(
        paths
            .data_root
            .join("versions/0.3.0-clean-device-test/dev-auth"),
        &unresolved_workload,
    )
    .unwrap();
    let workload = Command::new(&unresolved_workload)
        .arg("--version")
        .env_clear()
        .env("HOME", &user.dir)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(!workload.status.success());
    let workload_error = String::from_utf8(workload.stderr).unwrap();
    assert!(
        workload_error.contains("workload launcher is outside the installed alias set"),
        "{workload_error}"
    );
    assert!(!workload_error.contains("installation lock"));
    fs::remove_file(unresolved_workload).unwrap();
    fs::set_permissions(&installation_lock, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(user.dir.join(".local/bin/git"))
        .args(["future-command", "--new-option", "value"])
        .env_clear()
        .env("GIT_EDITOR", "code-insiders --wait")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let log = fs::read_to_string(upstream_log).unwrap();
    assert!(log.contains("editor=code-insiders --wait"));
    assert!(log.contains("arg=future-command"));
    assert!(log.contains("arg=--new-option"));
    assert!(log.contains("arg=value"));

    let rollback = rollback_at(&paths).unwrap();
    assert!(!rollback.transparent_launchers_active);
    assert!(!user.dir.join(".local/bin/git").exists());
    assert!(!user.dir.join(".local/bin/gh").exists());
}

#[cfg(target_os = "linux")]
fn run_missing_credential_stages_no_workload_launchers_child() {
    use dev_auth::deployment::{
        normalize_deployment, parse_deployment_document, DeploymentCliInput,
    };
    use dev_auth::setup::{build_plan, InstallMode, InstallRequest, SetupPaths};
    use dev_auth::setup_v3::{apply_setup_plan_v3, build_setup_plan_v3_at, render_setup_plan_v3};

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let root = tempfile::Builder::new()
        .prefix("dev-auth-inactive-home-")
        .tempdir_in(&user.dir)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let candidate = user.dir.parent().unwrap().join("product");
    let native_git = root.path().join("git");
    let native_gh = root.path().join("gh");
    let op = root.path().join("op");
    let ssh = root.path().join("ssh");
    let ssh_keygen = root.path().join("ssh-keygen");
    let future_agent = root.path().join("future-agent");
    for path in [
        &native_git,
        &native_gh,
        &op,
        &ssh,
        &ssh_keygen,
        &future_agent,
    ] {
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let policy = root.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"
[trusted_launchers]
future-agent = "{}"
[github_apps]
[credential_slots.automation]
users = ["{}"]
authority_caps = ["automation"]
secret_references = ["op://Automation/Agent/token"]
[authority_caps.automation]
secret_references = ["op://Automation/Agent/token"]
[workspace_caps]
"#,
            user.name,
            op.display(),
            native_git.display(),
            native_gh.display(),
            ssh.display(),
            ssh_keygen.display(),
            future_agent.display(),
            user.name,
        ),
    )
    .unwrap();
    let config = root.path().join("config.toml");
    fs::write(
        &config,
        br#"version = 2
[authority_profiles.automation]
cap = "automation"
signing = false
ssh = false
secret_references = []

[[workloads]]
name = "future-agent"
launcher = "future-agent"
profile = "automation"
secret_references = []
workspace_roots = []
[workloads.sandbox]
mode = "none"
"#,
    )
    .unwrap();
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let deployment = parse_deployment_document(
        format!(
            r#"schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "transparent"
administrator_policy = "{}"

[[users]]
name = "{}"
config = "{}"

[[credentials]]
slot = "automation"
intent = "enroll-if-absent"
"#,
            policy.display(),
            user.name,
            config.display(),
        )
        .as_bytes(),
    )
    .unwrap();
    let intent = normalize_deployment(Some(deployment), DeploymentCliInput::default()).unwrap();
    let paths = SetupPaths::user_only(&user.dir);
    let installation = build_plan(
        &paths,
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.3.0-inactive-test".into(),
            source_executable: candidate,
            native_git,
            native_gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    let plan = build_setup_plan_v3_at(intent, installation, false).unwrap();
    let (_, digest) = render_setup_plan_v3(&plan).unwrap();
    let report = apply_setup_plan_v3(&plan, &digest, &std::collections::BTreeMap::new()).unwrap();
    assert_eq!(report.input_required, ["automation"]);
    assert!(!report.verified);
    assert!(!user.dir.join(".local/bin/future-agent").exists());
    assert!(!user
        .dir
        .join(".local/share/dev-auth/workload-aliases-v1.json")
        .exists());
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_user_only_setup_is_idempotent_transparent_and_reversible() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_standalone_user_only_setup_child();
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    assert!(Command::new("/usr/bin/strip")
        .args(["--strip-debug"])
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "standalone_user_only_setup_is_idempotent_transparent_and_reversible",
            "--nocapture",
        ]),
        Duration::from_secs(90),
        "standalone setup acceptance subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn missing_credential_stages_no_workload_launchers() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child();
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "missing_credential_stages_no_workload_launchers",
            "--nocapture",
        ]),
        Duration::from_secs(90),
        "inactive setup acceptance subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn credential_helper(operation: &str, input: &str) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg(operation)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn get_failure_stops_git_from_falling_back_to_human_credentials() {
    let secret = "must-not-appear";
    let output = credential_helper(
        "get",
        &format!(
            "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\npassword={secret}\n\n"
        ),
    );
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains(secret));
}

#[test]
fn store_discards_git_supplied_secrets_without_output() {
    let output = credential_helper(
        "store",
        "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nusername=x-access-token\npassword=must-not-appear\n\n",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn store_accepts_git_eof_without_parsing_or_retaining_the_credential() {
    let output = credential_helper(
        "store",
        "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nusername=x-access-token\npassword=must-not-appear\n",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn help_is_product_generic_and_lists_the_bounded_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "enroll",
        "validate",
        "exec",
        "agent",
        "agent-endpoint",
        "ssh-load",
        "ssh-public",
        "workspace-status",
        "status",
        "purge",
    ] {
        assert!(help.contains(command));
    }
    assert!(!help.to_ascii_lowercase().contains("codex"));
    assert!(!help.to_ascii_lowercase().contains("homelab"));
}

#[test]
fn unsafe_gh_operations_are_rejected_before_configuration_or_credentials_are_read() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();

    for arguments in [
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--base",
            "main",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
            "--dry-run",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body-file=/proc/self/environ",
        ],
        vec!["pr", "comment", "42", "--body-file=private-link"],
        vec!["pr", "review", "42", "-aF/proc/self/environ"],
        vec!["pr", "merge", "42", "--admin", "--squash"],
        vec!["run", "download", "42", "--dir=/tmp"],
        vec!["repo", "view", "-RExampleOrg/sample-repo"],
        vec![
            "pr",
            "comment",
            "https://github.com/OtherOrg/other-repo/pull/42",
            "--body",
            "cross-repository",
        ],
        vec!["pr", "view", "42", "--unknown"],
    ] {
        let output = Command::new(&frontend)
            .args(&arguments)
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .output()
            .unwrap();

        assert!(!output.status.success(), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("configuration"), "{arguments:?}: {error}");
        assert!(!error.contains("credential"), "{arguments:?}: {error}");
    }
}

#[test]
fn invalid_ambient_gh_repository_is_rejected_before_configuration_or_runtime_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();

    let output = Command::new(&frontend)
        .args(["repo", "view", "--json", "nameWithOwner"])
        .env_clear()
        .env("GH_REPO", "not/an/exact/repository")
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("exact github.com owner/repository"),
        "{error}"
    );
    assert!(!error.contains("configuration"), "{error}");
    assert!(!runtime.path().join("dev-auth").exists());
}

#[test]
fn configured_git_resolves_literal_origin_without_caller_path_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "remote.origin.url",
            "https://github.com/ExampleOrg/too/many.git",
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/git"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Automation/app/private key"
repository_selection = "all"
discover_installations = true
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
"#,
    )
    .unwrap();
    fs::set_permissions(
        config_dir.join("config.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let attacker_bin = directory.path().join("attacker-bin");
    fs::create_dir(&attacker_bin).unwrap();
    let marker = directory.path().join("caller-path-git-ran");
    let attacker_git = attacker_bin.join("git");
    fs::write(
        &attacker_git,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nprintf 'https://github.com/ExampleOrg/too/many.git\\0'\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&attacker_git, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = private_runtime();

    let output = Command::new(&frontend)
        .args(["repo", "view", "--json", "nameWithOwner"])
        .current_dir(&repository)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin", attacker_bin.display()))
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("exactly owner/repository"),
        "unexpected error: {error}"
    );
    assert!(!error.contains("configuration"), "{error}");
    assert!(!error.contains("credential"), "{error}");
    assert!(!marker.exists());
    assert!(!runtime.path().join("dev-auth").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn offline_validation_is_value_free_and_pins_the_gh_protocol() {
    let sandbox = NativeUserSandbox::new();
    let home = &sandbox.home;
    let gh = home.join("gh");
    let binary = home.join("dev-auth");
    sandbox.install_binary(&binary);
    fs::write(
        &gh,
        "#!/bin/sh\n\
         [ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 91\n\
         [ -z \"${GH_TOKEN+x}\" ] || exit 92\n\
         [ -z \"${GITHUB_TOKEN+x}\" ] || exit 93\n\
         [ -z \"${GH_REPO+x}\" ] || exit 94\n\
         [ -z \"${DEV_AUTH_GH_CHILD+x}\" ] || exit 95\n\
         [ -z \"${DEV_AUTH_GH_GIT+x}\" ] || exit 96\n\
         case \"$HOME\" in */gh-sandbox/home) ;; *) exit 97 ;; esac\n\
         case \"$GH_CONFIG_DIR\" in */gh-sandbox/config) ;; *) exit 98 ;; esac\n\
         printf 'gh version 2.98.0 (2026-08-21)\\nhttps://github.com/cli/cli/releases/tag/v2.98.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let config_dir = home.join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "{}"
git = "/usr/bin/false"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[profiles.plan]
executables = ["/usr/bin/false"]
environment = {{ EXAMPLE_TOKEN = "op://Example Vault/plan/token" }}
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Example Vault/auth/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Example Vault/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        gh.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = bounded_output(sandbox.command(&binary, home).arg("validate"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "config_valid=true online=false declared_exec_profiles=1 declared_ssh_profiles=1 declared_secret_references=4\n"
    );
    assert!(output.stderr.is_empty());

    fs::write(
        &gh,
        "#!/bin/sh\nprintf 'gh version 2.99.0 (2026-08-28)\\nhttps://github.com/cli/cli/releases/tag/v2.99.0\\n'\n",
    )
    .unwrap();
    let rejected = bounded_output(sandbox.command(&binary, home).arg("validate"));
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = String::from_utf8(rejected.stderr).unwrap();
    assert!(error.contains("supported 2.98.0 protocol"));
    assert!(!error.contains("2.99.0"));
}

#[test]
fn one_released_binary_serves_the_git_helper_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg("get")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}

#[test]
fn one_released_binary_serves_every_declared_symlink_frontend() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    for frontend in [
        "git-dev-auth",
        "git-credential-dev-auth",
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
        "git-dev-auth.exe",
        "git-credential-dev-auth.exe",
        "gh-dev-auth.exe",
        "ssh-keygen-dev-auth.exe",
    ] {
        let path = directory.path().join(frontend);
        symlink(env!("CARGO_BIN_EXE_dev-auth"), &path).unwrap();
        let output = Command::new(&path)
            .arg("--help")
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{frontend}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with(&format!("{frontend}: ")),
            "{frontend}"
        );
    }
}

#[test]
fn managed_git_child_admits_only_its_exact_private_helper_identities() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    for (frontend, arguments) in [
        ("git-credential-dev-auth", vec!["get"]),
        ("ssh-keygen-dev-auth", vec!["--help"]),
    ] {
        let path = directory.path().join(frontend);
        symlink(env!("CARGO_BIN_EXE_dev-auth"), &path).unwrap();
        let mut command = Command::new(&path);
        command
            .args(arguments)
            .env_clear()
            .env("DEV_AUTH_GIT_CHILD", "1")
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path());
        let output = bounded_output(&mut command);
        assert!(!output.status.success(), "{frontend}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            !error.contains("unrecognized private child launcher identity"),
            "{frontend}: {error}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn public_git_frontend_uses_one_native_policy_and_propagates_managed_results() {
    let sandbox = NativeUserSandbox::new();
    let bin = sandbox.home.join("bin");
    let managed = sandbox.home.join("repos");
    let repository = managed.join("repository");
    let attacker_home = sandbox.root.join("attacker-home");
    let attacker_config = sandbox.root.join("attacker-config");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&attacker_home).unwrap();
    fs::create_dir_all(&attacker_config).unwrap();
    for path in [
        &bin,
        &managed,
        &repository,
        &attacker_home,
        &attacker_config,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let frontend = bin.join("git-dev-auth");
    let binary = bin.join("dev-auth");
    sandbox.install_binary(&binary);
    symlink(&binary, &frontend).unwrap();
    let fake_git = bin.join("git");
    let force_exit = sandbox.root.join("force-exit");
    fs::write(
        &fake_git,
        format!(
            r#"#!/bin/sh
if [ "${{1:-}}" = --version ]; then
  printf 'git version 2.53.0\n'
  exit 0
fi
while [ "${{1:-}}" = -c ]; do shift 2; done
case "${{1:-}}" in
  status)
    [ ! -e '{}' ] || exit 23
    exec /usr/bin/git "$@"
    ;;
  clone)
    for argument in "$@"; do destination=$argument; done
    /usr/bin/git init --quiet "$destination" || exit
    /usr/bin/git -C "$destination" config remote.origin.url https://github.com/ExampleOrg/cloned.git || exit
    exit 0
    ;;
  *) exec /usr/bin/git "$@" ;;
esac
"#,
            force_exit.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();
    let fake_gh = bin.join("gh");
    fs::write(
        &fake_gh,
        "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 91\nprintf 'gh version 2.98.0 (2026-08-21)\\nhttps://github.com/cli/cli/releases/tag/v2.98.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "remote.origin.url",
            "https://github.com/ExampleOrg/repository.git",
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let config_dir = sandbox.home.join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        sandbox.home.join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "{}"
git = "{}"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[git]
workspace_roots = ["~/repos"]
author_name = "Automation Worker"
author_email = "automation@example.invalid"
ssh_profile = "automation"
[github]
app_id = 42
private_key_ref = "op://Automation/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/authentication/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        fake_gh.display(),
        fake_git.display(),
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let human_marker = sandbox.root.join("human-helper-ran");
    let human_helper = sandbox.root.join("human-helper");
    fs::write(
        &human_helper,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", human_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&human_helper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        attacker_home.join(".gitconfig"),
        format!(
            "[core]\n\tfsmonitor = {}\n[credential]\n\thelper = !{}\n",
            human_helper.display(),
            human_helper.display()
        ),
    )
    .unwrap();
    fs::create_dir_all(attacker_config.join("dev-auth")).unwrap();
    fs::write(
        attacker_config.join("dev-auth/config.toml"),
        "this alternate policy must never be parsed\n",
    )
    .unwrap();

    let validate = bounded_output(sandbox.command(&binary, &repository).arg("validate"));
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let status = bounded_output(
        sandbox
            .command(&binary, &repository)
            .arg("workspace-status"),
    );
    assert_eq!(status.stdout, b"managed\n");
    assert!(status.stderr.is_empty());

    let managed_status = bounded_output(
        sandbox
            .command(&frontend, &repository)
            .args(["status", "--short"]),
    );
    assert!(
        managed_status.status.success(),
        "{}",
        String::from_utf8_lossy(&managed_status.stderr)
    );
    assert!(!human_marker.exists());

    let managed_version = bounded_output(sandbox.command(&frontend, &repository).arg("--version"));
    assert!(
        managed_version.status.success(),
        "{}",
        String::from_utf8_lossy(&managed_version.stderr)
    );
    assert_eq!(managed_version.stdout, b"git version 2.53.0\n");
    assert!(managed_version.stderr.is_empty());
    assert!(!human_marker.exists());

    let sentinel = "PUBLIC-CREDENTIAL-SENTINEL-DO-NOT-PRINT";
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            &format!("http.https://{sentinel}@example.invalid.extraheader"),
            "value",
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let rejected = bounded_output(
        sandbox
            .command(&frontend, &repository)
            .args(["status", "--short"]),
    );
    assert!(!rejected.status.success());
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains(sentinel));
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains(sentinel));
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "--unset-all",
            &format!("http.https://{sentinel}@example.invalid.extraheader"),
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let clone = bounded_output_with_timeout(
        sandbox.command(&frontend, &managed).args([
            "clone",
            "--no-checkout",
            "https://github.com/ExampleOrg/cloned.git",
            "cloned",
        ]),
        Duration::from_secs(60),
        "public managed clone subprocess",
    );
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    assert!(managed.join("cloned/.git").is_dir());
    assert!(!human_marker.exists());

    fs::write(&force_exit, b"exit 23\n").unwrap();
    let propagated = bounded_output(
        sandbox
            .command(&frontend, &repository)
            .args(["status", "--short"]),
    );
    assert_eq!(propagated.status.code(), Some(23));
    assert!(!human_marker.exists());
}

#[test]
fn internal_gh_children_do_not_forward_the_installation_token_to_git() {
    let directory = private_program_root();
    let home = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        format!(
            "#!/bin/sh\n[ -z \"${{GH_TOKEN+x}}\" ] || exit 90\n[ -z \"${{GITHUB_TOKEN+x}}\" ] || exit 91\n[ \"$GIT_TERMINAL_PROMPT\" = 0 ] || exit 92\n[ \"$1 $2\" = 'remote -v' ] || exit 93\nprintf passed > '{}'\n",
            home.path().join("git-child-result").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();

    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "{}"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
"#,
        upstream_git.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let marker = home.path().join("git-child-result");
    let output = Command::new(&git_frontend)
        .args(["remote", "-v"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", &upstream_git)
        .env("GH_TOKEN", "must-not-reach-git")
        .env("GITHUB_TOKEN", "must-not-reach-git")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "passed");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn internal_gh_git_child_rejects_url_scoped_repository_credential_helpers() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let marker = directory.path().join("credential-helper-ran");
    let helper = directory.path().join("credential-helper");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nif [ \"${{1:-}}\" = get ]; then\n  printf 'username=human\\npassword=human-secret\\n'\nfi\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "credential.https://github.com.helper",
            &format!("!{}", helper.display()),
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(&git_frontend)
        .args(["credential", "fill"])
        .current_dir(&repository)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", "/usr/bin/git")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let write_result = child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/repository.git\n\n");
    if let Err(error) = write_result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected credential-input write failure: {error}"
        );
    }
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("human-secret"));
}

#[test]
fn internal_gh_git_child_rejects_explicit_config_overrides() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let marker = directory.path().join("upstream-git-ran");
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();
    let home = tempfile::tempdir().unwrap();

    let output = Command::new(&git_frontend)
        .args(["-ccredential.helper=!attacker", "status"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", &upstream_git)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside the bounded read-only surface")
    );
}

#[test]
fn internal_gh_pager_copies_only_standard_input() {
    let directory = tempfile::tempdir().unwrap();
    let pager = directory.path().join("cat");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &pager).unwrap();
    let mut child = Command::new(&pager)
        .env_clear()
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("GH_TOKEN", "must-not-be-rendered")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"bounded output\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"bounded output\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn windows_credential_helper_name_preserves_fail_closed_git_output() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth.exe");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg("get")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}

#[test]
fn git_verification_does_not_require_the_secret_runtime_or_ssh_agent() {
    let directory = private_program_root();
    let helper = directory.path().join("ssh-keygen-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let verifier = directory.path().join("ssh-keygen");
    fs::write(
        &verifier,
        "#!/bin/sh\n[ \"$1\" = -Y ] && [ \"$2\" = verify ]\n",
    )
    .unwrap();
    fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();

    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[credential_store]
service = "test-dev-auth"
account = "service-token"
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/git"
ssh_add = "/usr/bin/false"
ssh_keygen = "{}"
[github]
app_id = 42
private_key_ref = "op://Automation/app/key"
repository_selection = "all"
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
discover_installations = true
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/auth/private key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/sign/private key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        verifier.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let absent_runtime = home.path().join("absent-runtime");
    let output = Command::new(&helper)
        .args(["-Y", "verify", "-n", "git"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_RUNTIME_DIR", &absent_runtime)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!absent_runtime.exists());
}
