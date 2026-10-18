#![cfg(test)]

//! Local startup-proof fixtures; these do not authorize grants or exercise cgroups.
use super::*;
use std::process::Stdio;
use wait_timeout::ChildExt;

const FIXTURE_CASE: &str = "DEV_AUTH_LAUNCH_GRANT_PROOF_CASE";
const FIXTURE_TARGET: &str = "DEV_AUTH_LAUNCH_GRANT_PROOF_TARGET";
const FIXTURE_MARKER: &str = "DEV_AUTH_LAUNCH_GRANT_PROOF_MARKER";
const FIXTURE_FD: RawFd = 198;
const FIXTURE_RELEASE_FD: RawFd = 199;
const FIXTURE_TEST: &str =
    "supervisor::launch_grant_tests::startup_proof_accepts_final_exec_outcomes";

fn transient_arguments(
    privilege: Option<&crate::privilege::grants::GrantRequest>,
    arguments: &[OsString],
) -> Vec<OsString> {
    transient_service_arguments(&TransientServiceRequest {
        duration_seconds: Some(86400),
        privilege,
        session_id: "0123456789abcdef0123456789abcdef",
        owner_uid: 1000,
        owner_gid: 1001,
        workload: "worker",
        cwd: Path::new("/home/example/work"),
        boundary_socket: Path::new("/run/dev-auth/workloads/0123456789abcdef0123456789abcdef.sock"),
        executable: Path::new("/usr/local/lib/dev-auth/versions/0.5.0/dev-auth"),
        tool_bin: Path::new("/run/dev-auth-workload-0123456789abcdef0123456789abcdef/tool-bin"),
        pinned_projection: None,
        arguments,
    })
    .unwrap()
}

#[test]
fn explicit_launch_grant_precedes_the_separator_and_preserves_literal_workload_arguments() {
    let privilege = crate::privilege::grants::GrantRequest {
        scope: crate::privilege::grants::GrantScope::Workload,
        authority: crate::privilege::grants::Authority::Administrator,
        duration_seconds: 43200,
        idle_seconds: Some(1800),
        uses: Some(3),
    };
    let payload = [
        OsString::from("--privilege-request"),
        OsString::from_vec(vec![b'x', 255]),
        OsString::from("--"),
        OsString::from("--startup-fd"),
        OsString::from("777"),
    ];
    let arguments = transient_arguments(Some(&privilege), &payload);
    let separator = arguments.len() - payload.len() - 1;
    assert_eq!(arguments[separator], "--");
    assert_eq!(&arguments[separator + 1..], &payload);
    assert_eq!(arguments[separator - 2], "--privilege-request");
    let decoded: crate::privilege::grants::GrantRequest =
        serde_json::from_str(arguments[separator - 1].to_str().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(decoded).unwrap(),
        serde_json::to_value(privilege).unwrap()
    );
}

#[test]
fn legacy_launch_omits_grant_transport_and_optional_request_fields_stay_absent() {
    let payload = [OsString::from("--privilege-request"), OsString::from("--")];
    let arguments = transient_arguments(None, &payload);
    let separator = arguments.len() - payload.len() - 1;
    assert_eq!(&arguments[separator + 1..], &payload);
    assert!(!arguments[..separator]
        .iter()
        .any(|value| value == "--privilege-request" || value == "--startup-fd"));

    let legacy = serde_json::json!({
        "scope": "workload",
        "authority": {"kind": "administrator"},
        "duration_seconds": 43200
    });
    let decoded: crate::privilege::grants::GrantRequest =
        serde_json::from_value(legacy.clone()).unwrap();
    decoded.validate().unwrap();
    assert!(decoded.idle_seconds.is_none() && decoded.uses.is_none());
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
}

struct FixtureChild(Child);

impl FixtureChild {
    fn wait(&mut self) -> ExitStatus {
        match self.0.wait_timeout(Duration::from_secs(10)).unwrap() {
            Some(status) => status,
            None => {
                self.0.kill().unwrap();
                self.0.wait().unwrap();
                panic!("isolated startup monitor did not finish within its fixture deadline");
            }
        }
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn spawn_fixture(case: &str, target: Option<&Path>) -> (OwnedFd, FixtureChild) {
    spawn_fixture_with_release(case, target, None, None)
}

fn spawn_fixture_with_release(
    case: &str,
    target: Option<&Path>,
    release_reader: Option<OwnedFd>,
    marker: Option<&Path>,
) -> (OwnedFd, FixtureChild) {
    let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let source_fd = writer.as_raw_fd();
    let release_fd = release_reader.as_ref().map(AsRawFd::as_raw_fd);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", FIXTURE_TEST])
        .env_clear()
        .env(FIXTURE_CASE, case)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(target) = target {
        command.env(FIXTURE_TARGET, target);
    }
    if let Some(marker) = marker {
        command.env(FIXTURE_MARKER, marker);
    }
    // SAFETY: after fork, only async-signal-safe descriptor syscalls run. The
    // duplicate belongs to this isolated child; the parent retains its writer.
    unsafe {
        command.pre_exec(move || {
            // Duplicate sources above both destinations before replacing any
            // descriptor, so even unusually high fixture FDs cannot collide.
            let proof_copy = nix::libc::fcntl(
                source_fd,
                nix::libc::F_DUPFD_CLOEXEC,
                FIXTURE_RELEASE_FD + 1,
            );
            if proof_copy < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let release_copy = match release_fd {
                Some(fd) => {
                    let copy =
                        nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, FIXTURE_RELEASE_FD + 1);
                    if copy < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Some(copy)
                }
                None => None,
            };
            if nix::libc::dup2(proof_copy, FIXTURE_FD) < 0
                || nix::libc::fcntl(FIXTURE_FD, nix::libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(copy) = release_copy {
                if nix::libc::dup2(copy, FIXTURE_RELEASE_FD) < 0
                    || nix::libc::fcntl(FIXTURE_RELEASE_FD, nix::libc::F_SETFD, 0) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                nix::libc::close(copy);
            }
            nix::libc::close(proof_copy);
            Ok(())
        });
    }
    let child = FixtureChild(command.spawn().unwrap());
    drop(writer);
    drop(release_reader);
    (reader, child)
}

fn run_fixture_if_requested() {
    let Ok(case) = std::env::var(FIXTURE_CASE) else {
        return;
    };
    // SAFETY: this numeric descriptor query neither takes ownership nor retains
    // a pointer; the exact test child received it from spawn_fixture.
    assert!(unsafe { nix::libc::fcntl(FIXTURE_FD, nix::libc::F_GETFD) } >= 0);
    // SAFETY: spawn_fixture transferred this pipe writer to the isolated child;
    // the check above establishes that it remains open before sole ownership.
    let mut writer = unsafe { File::from_raw_fd(FIXTURE_FD) };
    if case == "tracer-death-before-options" {
        // SAFETY: this exact isolated fixture owns its signal dispositions;
        // deliberately ignore TERM to prove the production SIGKILL safeguard.
        unsafe {
            nix::libc::signal(nix::libc::SIGTERM, nix::libc::SIG_IGN);
        }
        let mut command = Command::new(std::env::var_os(FIXTURE_TARGET).unwrap());
        command.arg(std::env::var_os(FIXTURE_MARKER).unwrap());
        exec_barrier::prepare(&mut command).unwrap();
        let target = FixtureChild(command.spawn().unwrap());
        // Native spawn closed its exec-error pipe, but no await_exec call has
        // applied EXITKILL yet. Retain this Child without reaping it.
        // The guard reaps on an unexpected unwind. The intended scenario keeps
        // this target held until the outer test SIGKILLs its monitor; waiting
        // here would invalidate the pre-EXITKILL tracer-death assertion.
        writer.write_all(&target.0.id().to_ne_bytes()).unwrap();
        loop {
            std::thread::park();
        }
    }
    if case == "early-monitor-death" {
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGKILL).unwrap();
        unreachable!();
    }
    let (target, arguments): (PathBuf, Vec<OsString>) = match case.as_str() {
        "success" => ("/usr/bin/sleep".into(), vec!["0.05".into()]),
        "fast-success" => ("/usr/bin/true".into(), vec![]),
        "nonzero" => ("/usr/bin/false".into(), vec![]),
        "target-signal" => ("/bin/sh".into(), vec!["-c".into(), "kill -TERM $$".into()]),
        "release-marker" => (
            std::env::var_os(FIXTURE_TARGET).unwrap().into(),
            vec![std::env::var_os(FIXTURE_MARKER).unwrap()],
        ),
        "fd-closed" | "missing-executable" | "missing-interpreter" => {
            (std::env::var_os(FIXTURE_TARGET).unwrap().into(), vec![])
        }
        _ => panic!("unknown isolated startup fixture"),
    };
    let outcome = if case == "release-marker" {
        // SAFETY: spawn_fixture_with_release transferred this exact read pipe
        // to the isolated monitor, which alone owns tracing and target waits.
        let release = unsafe { File::from_raw_fd(FIXTURE_RELEASE_FD) };
        launch_configured_workload_with_release(&target, &arguments, Some(writer), Some(release))
    } else {
        launch_configured_workload(&target, &arguments, Some(writer))
    };
    match outcome {
        Ok(status) => std::process::exit(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap()),
        ),
        Err(_) => std::process::exit(2),
    }
}

#[test]
fn startup_proof_accepts_final_exec_outcomes() {
    run_fixture_if_requested();
    let root = tempfile::tempdir().unwrap();
    let fd_target = root.path().join("check-proof-fd");
    fs::write(
        &fd_target,
        b"#!/bin/sh\nif [ -e /proc/self/fd/198 ]; then exit 91; fi\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fd_target, fs::Permissions::from_mode(0o700)).unwrap();
    for (case, expected) in [
        ("success", 0),
        ("fast-success", 0),
        ("nonzero", 1),
        ("target-signal", 128 + nix::libc::SIGTERM),
        ("fd-closed", 0),
    ] {
        let (reader, mut child) = spawn_fixture(case, Some(&fd_target));
        let proof = await_startup_proof(&reader);
        let status = child.wait();
        assert!(proof.is_ok(), "{case}: {proof:?}");
        assert_eq!(status.code(), Some(expected), "{case}: {status:?}");
    }
}

#[test]
fn startup_proof_rejects_missing_final_exec_and_early_monitor_death() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("absent-executable");
    let missing_interpreter = root.path().join("missing-interpreter");
    fs::write(
        &missing_interpreter,
        format!("#!{}\n", root.path().join("absent-interpreter").display()),
    )
    .unwrap();
    fs::set_permissions(&missing_interpreter, fs::Permissions::from_mode(0o700)).unwrap();
    for (case, target) in [
        ("missing-executable", missing.as_path()),
        ("missing-interpreter", missing_interpreter.as_path()),
        ("early-monitor-death", missing.as_path()),
    ] {
        let (reader, mut child) = spawn_fixture(case, Some(target));
        let proof = await_startup_proof(&reader);
        let status = child.wait();
        assert!(proof.is_err(), "accepted {case}");
        if case == "early-monitor-death" {
            assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        } else {
            assert_eq!(status.code(), Some(2));
        }
    }
}

#[test]
fn startup_proof_rejects_missing_malformed_and_duplicate_announcements() {
    for bytes in [b"".as_slice(), &[0], &[2], &[1, 1], &[1, 2], &[1, 255]] {
        let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        if !bytes.is_empty() {
            assert_eq!(nix::unistd::write(&writer, bytes).unwrap(), bytes.len());
        }
        drop(writer);
        assert!(await_startup_proof(&reader).is_err(), "accepted {bytes:?}");
    }
}

fn release_marker_target(root: &Path) -> PathBuf {
    let target = root.join("write-release-marker");
    fs::write(&target, b"#!/bin/sh\nprintf released > \"$1\"\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    target
}

#[test]
fn proved_final_exec_cannot_write_its_marker_until_explicit_release() {
    let root = tempfile::tempdir().unwrap();
    let target = release_marker_target(root.path());
    let marker = root.path().join("target-ran");
    let (release_reader, release_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let (proof_reader, mut child) = spawn_fixture_with_release(
        "release-marker",
        Some(&target),
        Some(release_reader),
        Some(&marker),
    );
    let proof = await_startup_proof(&proof_reader);
    assert!(proof.is_ok(), "final native exec was not proved: {proof:?}");
    assert!(!marker.exists(), "target ran before execution release");
    assert!(child.0.try_wait().unwrap().is_none());

    assert_eq!(nix::unistd::write(&release_writer, &[1]).unwrap(), 1);
    drop(release_writer);
    assert_eq!(child.wait().code(), Some(0));
    assert_eq!(fs::read(&marker).unwrap(), b"released");
}

#[test]
fn a_closed_execution_release_stops_the_proved_target_without_its_marker() {
    let root = tempfile::tempdir().unwrap();
    let target = release_marker_target(root.path());
    let marker = root.path().join("target-must-not-run");
    let (release_reader, release_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let (proof_reader, mut child) = spawn_fixture_with_release(
        "release-marker",
        Some(&target),
        Some(release_reader),
        Some(&marker),
    );
    let proof = await_startup_proof(&proof_reader);
    assert!(proof.is_ok(), "final native exec was not proved: {proof:?}");
    assert!(!marker.exists(), "target ran before execution release");

    drop(release_writer);
    assert_eq!(child.wait().code(), Some(2));
    assert!(!marker.exists(), "target ran after release was closed");
}

#[test]
fn tracer_death_before_exitkill_cannot_release_the_configured_target() {
    let root = tempfile::tempdir().unwrap();
    let target = release_marker_target(root.path());
    let marker = root.path().join("must-not-run-after-tracer-death");
    let (proof, mut monitor) = spawn_fixture_with_release(
        "tracer-death-before-options",
        Some(&target),
        None,
        Some(&marker),
    );
    let mut descriptors = [PollFd::new(proof.as_fd(), PollFlags::POLLIN)];
    assert_eq!(poll(&mut descriptors, 5000_u16).unwrap(), 1);
    let mut child_pid = [0_u8; 4];
    File::from(proof).read_exact(&mut child_pid).unwrap();
    let child_pid = u32::from_ne_bytes(child_pid);
    let child_pid = rustix::process::Pid::from_raw(child_pid as i32).unwrap();
    let witness =
        rustix::process::pidfd_open(child_pid, rustix::process::PidfdFlags::empty()).unwrap();
    let mut exited = [PollFd::new(witness.as_fd(), PollFlags::POLLIN)];
    assert_eq!(poll(&mut exited, PollTimeout::ZERO).unwrap(), 0);
    assert!(!marker.exists());
    monitor.0.kill().unwrap();
    assert_eq!(monitor.wait().signal(), Some(nix::libc::SIGKILL));
    assert_eq!(poll(&mut exited, 5000_u16).unwrap(), 1);
    assert!(
        !marker.exists(),
        "target instructions ran after its pre-EXITKILL tracer died"
    );
}

#[test]
fn sandbox_startup_descriptor_is_separate_from_literal_workload_arguments() {
    let sandbox = SandboxLaunch {
        executable: "/usr/bin/bwrap".into(),
        arguments: vec!["--unshare-all".into()],
        inherited_descriptor_arguments: vec!["--preserve-fds".into(), "{count}".into()],
        argument_separator: true,
        network_namespace: SandboxNetworkNamespace::Inherit,
    };
    let payload = ["--startup-fd".into(), "777".into(), "--".into()];
    for startup_fd in [None, Some(FIXTURE_FD), Some(2)] {
        let result = sandboxed_workload_arguments(
            &SandboxedWorkloadRequest {
                sandbox: &sandbox,
                parent_network_namespace: 42,
                dev_auth_executable: Path::new("/usr/local/lib/dev-auth/versions/0.5.0/dev-auth"),
                session_id: "0123456789abcdef0123456789abcdef",
                workload: "worker",
                launcher: Path::new("/opt/worker/bin/worker"),
                workload_arguments: &payload,
                startup_fd,
                execution_release_fd: startup_fd.map(|_| FIXTURE_RELEASE_FD),
            },
            &[],
        );
        if startup_fd == Some(2) {
            assert!(result.is_err());
            continue;
        }
        let arguments = result.unwrap();
        let separator = arguments.len() - payload.len() - 1;
        assert_eq!(arguments[separator], "--");
        assert_eq!(&arguments[separator + 1..], &payload);
        if startup_fd.is_some() {
            assert_eq!(arguments[separator - 4], "--startup-fd");
            assert_eq!(
                arguments[separator - 3],
                OsString::from(FIXTURE_FD.to_string())
            );
            assert_eq!(arguments[separator - 2], "--exec-release-fd");
            assert_eq!(
                arguments[separator - 1],
                OsString::from(FIXTURE_RELEASE_FD.to_string())
            );
        } else {
            assert!(!arguments[..separator]
                .iter()
                .any(|argument| argument == "--startup-fd"));
        }
    }
}

#[test]
fn current_adapter_template_is_authoritative_after_native_admission() {
    let mut current = SandboxLaunch {
        executable: "/usr/bin/bwrap".into(),
        arguments: vec!["--unshare-all".into()],
        inherited_descriptor_arguments: vec!["--preserve-fds".into(), "{count}".into()],
        argument_separator: true,
        network_namespace: SandboxNetworkNamespace::Isolated,
    };
    let mut transported = current.clone();
    transported.inherited_descriptor_arguments.clear();
    assert!(require_current_sandbox_launch(Some(&transported), Some(&current)).is_ok());
    assert!(require_current_sandbox_launch(None, Some(&current)).is_err());
    assert!(require_current_sandbox_launch(Some(&transported), None).is_err());
    current.arguments.push("--share-net".into());
    assert!(require_current_sandbox_launch(Some(&transported), Some(&current)).is_err());
}
