//! Synthetic credential material, real systemd broker and protected dispatcher.
use super::*;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

pub(super) fn prepare(account: &nix::unistd::User) -> (Vec<u8>, Vec<u8>) {
    let runtime = PathBuf::from(format!("/run/user/{}", account.uid));
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    nix::unistd::chown(&runtime, Some(account.uid), Some(account.gid)).unwrap();
    publish(Path::new("/usr/local/libexec/dev-auth-fixture-provider"), br##"#!/bin/sh
[ "$OP_SERVICE_ACCOUNT_TOKEN" = 'fixture-service-account' ] || exit 90
case "$*" in
  'user get --me --format json') printf '%s' '{"id":"fixture","state":"ACTIVE","type":"SERVICE_ACCOUNT"}' ;;
  'read --no-newline op://Fixture/Token/value') printf '%s' 'fixture-delivered-secret' ;;
  *) exit 91 ;;
esac
"##, 0o755);
    publish(Path::new("/usr/local/libexec/dev-auth-fixture-worker"), br##"#!/bin/sh
set -eu
if [ "${1-}" = hold ]; then
  fixture_case=$2
  /usr/bin/setsid /usr/bin/bash -c 'trap "" TERM; printf "%s\n" "$$" > "$HOME/descendant-$1.pid"; while :; do /usr/bin/sleep 1; done' -- "$fixture_case" </dev/null >/dev/null 2>&1 &
  printf '%s\n' "$$" > "$HOME/worker-$fixture_case.pid"
  while :; do /usr/bin/sleep 1; done
fi
/usr/local/bin/dev-auth validate --component providers --online --non-interactive --json
[ "$(/usr/local/bin/dev-auth secret read token --non-interactive)" = 'fixture-delivered-secret' ]
/usr/local/bin/dev-auth secret exec --stdin token --non-interactive -- /usr/bin/bash -c 'IFS= read -r value || :; test "$value" = fixture-delivered-secret'
printf 'workload-credential-check=passed\n'
"##, 0o755);
    crate::setup::enroll_system_service_credential_slot("automation", b"fixture-service-account")
        .unwrap();
    let name = &account.name;
    let policy = format!(
        r#"schema = "dev-auth-administrator-policy-v3"
mode = "strong"
allowed_users = ["{name}"]
[programs]
git = "/usr/bin/true"
gh = "/usr/bin/false"
ssh = "/usr/bin/true"
ssh_keygen = "/usr/bin/true"
[trusted_launchers]
worker = "/usr/local/libexec/dev-auth-fixture-worker"
[credentials.providers.primary]
kind = "one_password"
executable = "/usr/local/libexec/dev-auth-fixture-provider"
[credentials.credential_slots.automation]
provider = "primary"
users = ["{name}"]
[credentials.resources.token]
credential_slot = "automation"
reference = "op://Fixture/Token/value"
kind = "exportable"
purposes = ["read"]
projections = ["stdin"]
[credentials.resource_caps.worker]
users = ["{name}"]
[credentials.resource_caps.worker.resources.token]
purposes = ["read"]
projections = ["stdin"]
[workload_caps.worker]
users = ["{name}"]
resource_cap = "worker"
launchers = ["worker"]
admission = ["enrolled_noninteractive"]
max_duration_seconds = 60
"#
    )
    .into_bytes();
    let config = br#"schema = "dev-auth-user-config-v3"
[authority_profiles.worker]
cap = "worker"
[authority_profiles.worker.resources.token]
purposes = ["read"]
projections = ["stdin"]
[[workloads]]
name = "worker"
profile = "worker"
launcher = "worker"
admission = "enrolled_noninteractive"
duration_seconds = 60
[workloads.resources.token]
purposes = ["read"]
projections = ["stdin"]

[[workloads]]
name = "short-worker"
profile = "worker"
launcher = "worker"
admission = "enrolled_noninteractive"
duration_seconds = 8
[workloads.resources.token]
purposes = ["read"]
projections = ["stdin"]
"#
    .to_vec();
    (policy, config)
}

pub(super) fn require_credential_operation(account: &nix::unistd::User, executable: &Path) {
    let output = run_workload(account, executable, "worker", &[]).unwrap();
    assert!(
        output.status.success(),
        "workload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("workload-credential-check=passed"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("fixture-delivered-secret") && !stdout.contains("fixture-service-account")
    );
    let report: serde_json::Value =
        serde_json::from_str(stdout.lines().find(|line| line.starts_with('{')).unwrap()).unwrap();
    assert_eq!(report["authority"], "installed_broker");
    assert_eq!(report["exit_code"], 0);
    require_clean_workload_state();
}

pub(super) fn exercise(account: &nix::unistd::User, executable: &Path) {
    require_credential_operation(account, executable);
    let mut failed = Vec::new();
    for case in ["expiry", "revocation", "dispatcher", "broker"] {
        let result = std::panic::catch_unwind(|| exercise_failure(account, executable, case));
        require_clean_workload_state();
        if result.is_err() {
            failed.push(case);
        }
    }
    assert!(failed.is_empty(), "lifecycle failures: {failed:?}");
    let restored = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    let restored: serde_json::Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(
        restored["verified"], true,
        "public strong restoration failed: {restored}"
    );
    assert_eq!(restored["changed"], true);
    assert!(
        crate::setup::system_service_credential_slot_ready("automation"),
        "restoration reversed enrollment"
    );
    let retry = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    let retry: serde_json::Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry["verified"], true);
    assert_eq!(retry["changed"], false);
    assert!(!Path::new("/usr/local/bin/dev-auth").exists());
    assert!(!Path::new("/etc/dev-auth/policy.toml").exists());
    assert!(!Path::new("/run/dev-auth/broker.sock").exists());
    assert!(!Path::new("/run/dev-auth/control.sock").exists());
}

fn run_workload(
    account: &nix::unistd::User,
    executable: &Path,
    workload: &str,
    arguments: &[&str],
) -> Result<dev_tools_command::BoundedCommandOutput, dev_tools_command::BoundedCommandError> {
    let held = dev_tools_command::HeldExecutable::open(executable).unwrap();
    let mut selected = held.command(std::ffi::OsStr::new("dev-auth")).unwrap();
    selected
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&account.dir)
        .args(["workload", "launch", workload, "--non-interactive", "--"])
        .args(arguments);
    dev_tools_command::run_prepared_bounded_command(
        &mut selected,
        Duration::from_secs(40),
        64 * 1024,
    )
}

fn require_clean_workload_state() {
    let status = command(
        Path::new("/usr/bin/systemctl"),
        &[
            "--system",
            "list-units",
            "dev-auth-workload-*",
            "--no-legend",
            "--no-pager",
        ],
    );
    assert!(status.status.success());
    assert!(
        status.stdout.is_empty(),
        "workload unit survived completed launch"
    );
    let lock = crate::setup_transition::lock_path(DeploymentMode::Strong, None).unwrap();
    assert!(
        InstallationLock::try_acquire(&lock).unwrap().is_some(),
        "workload retained setup exclusion after completion"
    );
}

fn wait_until(mut condition: impl FnMut() -> bool, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn pidfd(pid: u32) -> OwnedFd {
    rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
        rustix::process::PidfdFlags::empty(),
    )
    .unwrap()
}

fn exited(descriptor: &OwnedFd) -> bool {
    let mut poll = [nix::poll::PollFd::new(
        descriptor.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    nix::poll::poll(&mut poll, 0_u16).unwrap() > 0
}

fn selected_dispatcher(workload: &str) -> OwnedFd {
    let mut selected = Vec::new();
    for process in fs::read_dir("/proc").unwrap() {
        let process = process.unwrap();
        let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(command) = fs::read(process.path().join("cmdline")) else {
            continue;
        };
        let parts = command.split(|byte| *byte == 0).collect::<Vec<_>>();
        if parts.first() == Some(&b"/usr/local/lib/dev-auth/dev-auth-workload-launcher".as_slice())
            && parts
                .windows(2)
                .any(|pair| pair == [b"--workload".as_slice(), workload.as_bytes()])
        {
            selected.push(pid);
        }
    }
    assert_eq!(selected.len(), 1, "fixture dispatcher is ambiguous");
    pidfd(selected[0])
}

fn exercise_failure(account: &nix::unistd::User, executable: &Path, case: &str) {
    eprintln!("fixture lifecycle case: {case}");
    let workload = if case == "expiry" {
        "short-worker"
    } else {
        "worker"
    };
    let worker_path = account.dir.join(format!("worker-{case}.pid"));
    let descendant_path = account.dir.join(format!("descendant-{case}.pid"));
    assert!(!worker_path.exists() && !descendant_path.exists());
    let read_pid = |path: &Path| -> Option<u32> {
        let bytes = fs::read_to_string(path).ok()?;
        (bytes.len() <= 32).then_some(())?;
        bytes.trim().parse::<u32>().ok().filter(|pid| *pid != 0)
    };
    std::thread::scope(|scope| {
        let running = scope.spawn(|| run_workload(account, executable, workload, &["hold", case]));
        assert!(
            wait_until(
                || read_pid(&worker_path).is_some() && read_pid(&descendant_path).is_some(),
                Duration::from_secs(6)
            ),
            "{case}: worker did not reach its ready handshake"
        );
        let worker = read_pid(&worker_path).unwrap();
        let descendant = read_pid(&descendant_path).unwrap();
        let cgroup = fs::read_to_string(format!("/proc/{worker}/cgroup")).unwrap();
        let memberships = cgroup
            .lines()
            .filter_map(|line| line.strip_prefix("0::"))
            .collect::<Vec<_>>();
        assert_eq!(memberships.len(), 1, "ambiguous fixture cgroup: {cgroup:?}");
        // The exec controller may observe an outer cgroup-namespace prefix.
        // PIDs are private to this container; select only its exact product unit.
        let membership = Path::new(memberships[0]);
        assert_eq!(
            membership.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("system.slice")),
            "unexpected fixture cgroup: {cgroup:?}"
        );
        let group = membership.file_name().unwrap().to_str().unwrap();
        let session = group
            .strip_prefix("dev-auth-workload-")
            .unwrap()
            .strip_suffix(".service")
            .unwrap();
        assert_eq!(session.len(), 32);
        assert!(session.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            fs::read_to_string(format!("/proc/{descendant}/cgroup")).unwrap(),
            cgroup
        );
        let worker = pidfd(worker);
        let descendant = pidfd(descendant);
        match case {
            "expiry" => {}
            "revocation" => {
                assert!(matches!(
                    crate::broker_client::control_request_system(
                        crate::control_protocol::ControlRequest::Revoke {
                            session_id: session.into()
                        }
                    )
                    .unwrap(),
                    crate::control_protocol::ControlResponse::Revoked { existed: true }
                ));
            }
            "dispatcher" => {
                rustix::process::pidfd_send_signal(
                    selected_dispatcher(workload),
                    rustix::process::Signal::KILL,
                )
                .unwrap();
            }
            "broker" => {
                assert!(command(
                    Path::new("/usr/bin/systemctl"),
                    &[
                        "--system",
                        "kill",
                        "--signal=KILL",
                        "dev-auth-broker.service"
                    ]
                )
                .status
                .success());
            }
            _ => unreachable!(),
        }
        let terminal = wait_until(
            || exited(&worker) && exited(&descendant),
            Duration::from_secs(20),
        );
        if !terminal {
            assert!(
                command(
                    Path::new("/usr/bin/systemctl"),
                    &["--system", "stop", group]
                )
                .status
                .success(),
                "fixture cleanup failed"
            );
        }
        let output = running.join().unwrap().unwrap();
        assert!(
            terminal,
            "{case}: workload or detached descendant survived the cleanup bound"
        );
        assert!(
            !output.status.success(),
            "{case}: interruption reported successful workload completion"
        );
    });
}
