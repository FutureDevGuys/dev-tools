use super::*;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

const SESSION: &str = "abcdef0123456789abcdef0123456789";

#[test]
#[ignore = "requires an owned disposable systemd container; never run on the host"]
fn dedicated_broker_retains_setup_lease_after_dispatcher_returns() {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(nix::unistd::Uid::effective().is_root());
    assert!(Path::new("/run/.containerenv").is_file());
    let socket = Path::new("/run/dev-auth-lease-fixture.sock");
    let listener = UnixListener::bind(socket).unwrap();
    let paths = crate::setup::SetupPaths::strong();
    let digest = "a".repeat(64);
    crate::setup_transition::begin(&paths, 0, &digest, || Ok(b"fixture retention".to_vec()))
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "broker_server::native_lease_tests::dedicated_broker_child",
            "--nocapture",
        ])
        .env_clear()
        .env("DEV_AUTH_BROKER_LEASE_CHILD", "1")
        .uid(1000)
        .gid(1000)
        .stdin(Stdio::from(OwnedFd::from(listener)))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let result = std::panic::catch_unwind(|| {
        let request = || ControlRequest::Prepare {
            session: Box::new(crate::linux_admission::PendingSessionRegistration {
                session_id: SESSION.into(),
                owner_uid: 1001,
                owner_gid: 1001,
                execution_pid: std::process::id(),
                workload: "fixture".into(),
                profile: "fixture".into(),
                authority: crate::linux_admission::SessionAuthorityGrant {
                    logical: None,
                    hard_deadline_boot_ms: None,
                    github: None,
                    signing: None,
                    release_signing: None,
                    ssh: Vec::new(),
                },
                cgroup: format!("/sys/fs/cgroup/system.slice/dev-auth-workload-{SESSION}.service")
                    .into(),
                expires_at_unix: OffsetDateTime::now_utc().unix_timestamp() + 60,
            }),
        };
        assert!(
            crate::broker_client::control_request_at(socket, request()).is_err(),
            "pending generation admitted a control request"
        );
        crate::setup_transition::accept(&paths, 0, &digest).unwrap();
        assert_eq!(
            crate::broker_client::control_request_at(socket, request()).unwrap(),
            ControlResponse::Accepted
        );
        let lock =
            crate::setup_transition::lock_path(crate::deployment::DeploymentMode::Strong, None)
                .unwrap();
        assert!(dev_tools_installation::InstallationLock::try_acquire(&lock)
            .unwrap()
            .is_none());
        assert!(matches!(
            crate::broker_client::control_request_at(socket, request()).unwrap(),
            ControlResponse::Denied { .. }
        ));
        assert!(dev_tools_installation::InstallationLock::try_acquire(&lock)
            .unwrap()
            .is_none());
        assert!(matches!(
            crate::broker_client::control_request_at(
                socket,
                ControlRequest::Revoke {
                    session_id: SESSION.into()
                }
            )
            .unwrap(),
            ControlResponse::Revoked { .. }
        ));
        assert!(dev_tools_installation::InstallationLock::try_acquire(&lock)
            .unwrap()
            .is_some());
    });
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    fs::remove_file(socket).unwrap();
    result.unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "child fixture for dedicated broker identity"]
fn dedicated_broker_child() {
    if std::env::var("DEV_AUTH_BROKER_LEASE_CHILD").as_deref() != Ok("1") {
        return;
    }
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 1000);
    assert!(fs::File::open(crate::setup_transition::state_path(
        &crate::setup::SetupPaths::strong()
    ))
    .is_err());
    let listener = UnixListener::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
    let registry = LinuxSessionRegistry::new();
    let operations = SessionOperations::default();
    for _ in 0..3 {
        let (mut stream, _) = listener.accept().unwrap();
        handle_control_connection(
            &mut stream,
            &registry,
            &operations,
            &UnavailableCapabilityBackend,
        )
        .unwrap();
    }
    assert!(operations.setup_leases.lock().unwrap().is_empty());
}

#[test]
fn control_lease_transport_rejects_multiple_and_truncated_descriptors() {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    for count in [1_usize, 2, 8] {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let file = tempfile::tempfile().unwrap();
        let descriptors = vec![file.as_fd(); count];
        let mut storage = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = SendAncillaryBuffer::new(&mut storage);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        assert_eq!(
            sendmsg(
                &sender,
                &[std::io::IoSlice::new(&[0, 0, 0, 2, b'{', b'}'])],
                &mut ancillary,
                SendFlags::NOSIGNAL
            )
            .unwrap(),
            6
        );
        let observed = read_control_frame(&mut receiver);
        if count == 1 {
            let (bytes, fd) = observed.unwrap();
            assert_eq!(bytes, b"{}");
            assert!(rustix::io::fcntl_getfd(fd.unwrap())
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC));
        } else {
            assert!(observed.is_err());
        }
    }
}
