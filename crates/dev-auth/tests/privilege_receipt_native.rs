#![cfg(all(target_os = "linux", feature = "native-privilege-fixture"))]
#[path = "support/privilege_receipt_native_contract.rs"]
mod contract;
use contract::{Case, Input};
use dev_auth::privilege::{custody, policy, protocol};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn real_adapter_matrix_is_finite_and_rejects_command_injection() {
    let value = serde_json::json!({"schema":"dev-auth-receipt-install-native-input-v1","case":"transaction","dev_auth":"/a","dev_auth_sha256":"33".repeat(32),"controller":"/b","controller_sha256":"11".repeat(32),"fixture_root":"/var/tmp/dev-auth-receipt-native-one","approval_plan":"/c","approval_sha256":"22".repeat(32),"receipt_a":[],"receipt_b":[],"command":"sudo arbitrary"});
    assert!(serde_json::from_value::<Input>(value).is_err());
    for name in ["transaction", "revoke", "hard-expiry", "alias-denied"] {
        assert!(serde_json::from_value::<Case>(serde_json::json!(name)).is_ok());
    }
}

#[test]
#[ignore = "requires ordinary installed candidate, real standalone installer/root receipt generations, explicit root driver and native administrator approval in disposable systemd guest"]
fn real_receipt_installer_reuses_one_approved_grant() {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_RECEIPT_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(Path::new("/run/.containerenv").is_file());
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    dev_auth::privilege::platform::CoreDumpProfile::capture().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    assert_ne!(uid, 0);
    assert_eq!(nix::unistd::geteuid().as_raw(), uid);
    let path = PathBuf::from(
        std::env::var_os("DEV_AUTH_NATIVE_RECEIPT_INPUT").expect("explicit native input required"),
    );
    assert_eq!(path.file_name().unwrap(), "real-input.json");
    let (input, approval) = contract::read(&path, uid).unwrap();
    assert_eq!(approval.request.owner_uid, uid);
    assert_eq!(path, input.fixture_root.join("real-input.json"));
    assert_eq!(
        policy::digest(&fs::read(&input.dev_auth).unwrap()),
        input.dev_auth_sha256
    );

    assert_eq!(
        input.approval_plan.parent(),
        Some(input.fixture_root.as_path())
    );
    let root_meta = fs::symlink_metadata(&input.fixture_root).unwrap();
    assert_eq!(root_meta.uid(), uid);
    assert_eq!(root_meta.mode() & 0o7777, 0o700);
    assert_eq!(
        policy::digest(&fs::read(&input.controller).unwrap()),
        input.controller_sha256
    );
    // The candidate under test must be the normal product binary, not a fixture
    // subject. Its supplied policy contains only the production adapter.
    assert!(approval
        .operations
        .values()
        .all(|op| op.protocol == dev_auth::privilege::receipt_install::PROTOCOL));
    for leaf in [
        "session",
        "session-result.json",
        "real-work-complete",
        "interrupt-ready",
        "unexpected-controller-release",
        "alias-terminal",
    ] {
        assert!(
            !input.fixture_root.join(leaf).exists(),
            "fresh fixture required"
        );
    }
    marker(
        &input,
        "real-driver-ready",
        input.approval_sha256.as_bytes(),
        Duration::from_secs(5),
    );
    let result = input.fixture_root.join("session-result.json");
    let mut child = Command::new(&input.dev_auth)
        .args(["privilege", "request", "--plan"])
        .arg(&input.approval_plan)
        .args([
            "--sha256",
            &input.approval_sha256,
            "--authorize",
            "polkit",
            "--result-file",
        ])
        .arg(&result)
        .arg("--")
        .arg(&input.controller)
        .arg("receipt-controller")
        .arg(&path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(approval.request.hard_seconds + 150);
    if input.case == Case::AliasDenied {
        let status = wait_child(&mut child, deadline);
        if let Ok(session) =
            fs::read_to_string(input.fixture_root.join("unexpected-controller-release"))
        {
            let _ = Command::new(&input.dev_auth)
                .args(["privilege", "revoke", "--session", &session, "--json"])
                .status();
            panic!("protected bind alias passed root admission");
        }
        assert!(!status.success());
        let observation: protocol::Observation =
            policy::parse(&custody::read_document(&result, uid, 0o600).expect(
                "authenticated root terminal required; declined approval is not alias acceptance",
            ))
            .unwrap();
        assert!(observation.cleanup_complete);
        assert_eq!(observation.outcome, "failed");
        custody::write_new_document(
            &input.fixture_root.join("alias-terminal"),
            input.approval_sha256.as_bytes(),
            uid,
        )
        .unwrap();
        marker(
            &input,
            "real-driver-complete",
            input.approval_sha256.as_bytes(),
            Duration::from_secs(10),
        );
        return;
    }
    while !input.fixture_root.join("session").exists() {
        assert!(Instant::now() < deadline);
        assert!(
            child.try_wait().unwrap().is_none(),
            "native admission failed before controller"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let session = fs::read_to_string(input.fixture_root.join("session")).unwrap();
    protocol::token(&session).unwrap();
    let domain = HeldDomain::open(PathBuf::from(format!(
        "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
    )));
    match input.case {
        Case::Transaction => {
            while !input.fixture_root.join("real-work-complete").exists() {
                assert!(Instant::now() < deadline);
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "real installer workflow failed before completion"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let revoked = Command::new(&input.dev_auth)
                .args(["privilege", "revoke", "--session", &session, "--json"])
                .output()
                .unwrap();
            assert!(revoked.status.success(), "real workflow revocation failed");
        }
        Case::Revoke => {
            marker(
                &input,
                "real-stopped",
                b"install-a",
                Duration::from_secs(90),
            );
            let revoked = Command::new(&input.dev_auth)
                .args(["privilege", "revoke", "--session", &session, "--json"])
                .output()
                .unwrap();
            assert!(
                revoked.status.success(),
                "stopped real installer revocation failed"
            );
        }
        Case::HardExpiry => {
            marker(
                &input,
                "real-stopped",
                b"install-a",
                Duration::from_secs(90),
            );
        }
        Case::AliasDenied => unreachable!(),
    }
    let status = wait_child(&mut child, deadline);
    assert!(
        status.success() || input.case == Case::HardExpiry,
        "native request lost successful cleanup"
    );
    let observation: protocol::Observation =
        policy::parse(&custody::read_document(&result, uid, 0o600).unwrap()).unwrap();
    assert!(observation.cleanup_complete);
    if input.case == Case::HardExpiry {
        assert!(
            dev_auth::linux_platform::boot_time_millis().unwrap()
                >= observation.hard_deadline_boot_ms,
            "grant ended before the actual hard deadline"
        );
        if status.success() {
            assert!(observation.terminal_success());
        } else {
            // The independent hard timer may kill the coordinator before it
            // sends a terminal record. Only this existing fallback is allowed.
            assert_eq!(observation.outcome, "failed");
            assert_eq!(
                observation.error_kind.as_deref(),
                Some("native_terminal_cleanup_unproven")
            );
        }
    }
    assert!(domain.empty_or_removed());
    let directory = dev_auth::privilege::runtime::session_directory(&session).unwrap();
    assert!(!directory.join("control.sock").exists());
    assert!(!directory.join("handoff.sock").exists());
    marker(
        &input,
        "real-driver-complete",
        session.as_bytes(),
        Duration::from_secs(15),
    );
    let stale = Command::new(&input.dev_auth)
        .args([
            "privilege",
            "execute-plan",
            "--session",
            &session,
            "--operation",
            "receipt",
            "--plan-id",
            "install-a",
        ])
        .output()
        .unwrap();
    assert!(!stale.status.success());
}
fn wait_child(child: &mut std::process::Child, deadline: Instant) -> std::process::ExitStatus {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "real receipt fixture timed out; native run failed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn marker(input: &Input, name: &str, expected: &[u8], budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let path = input.fixture_root.join(name);
        if let Ok(m) = fs::symlink_metadata(&path) {
            assert!(m.is_file());
            assert_eq!(m.uid(), 0);
            assert_eq!(m.mode() & 0o7777, 0o644);
            assert_eq!(m.nlink(), 1);
            assert_eq!(fs::read(path).unwrap(), expected);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "root real-installer driver did not prove its milestone"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
struct HeldDomain {
    path: PathBuf,
    file: File,
    parent: File,
    identity: (u64, u64),
    parent_identity: (u64, u64),
}
impl HeldDomain {
    fn open(path: PathBuf) -> Self {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        let m = file.metadata().unwrap();
        assert_eq!(m.uid(), 0);
        assert_eq!(
            rustix::fs::fstatfs(&file).unwrap().f_type as u64,
            0x6367_7270
        );
        let parent = File::open(path.parent().unwrap()).unwrap();
        let p = parent.metadata().unwrap();
        Self {
            path,
            file,
            parent,
            identity: (m.dev(), m.ino()),
            parent_identity: (p.dev(), p.ino()),
        }
    }
    fn empty_or_removed(&self) -> bool {
        let p = self.parent.metadata().unwrap();
        let named = fs::symlink_metadata(self.path.parent().unwrap()).unwrap();
        assert_eq!((p.dev(), p.ino()), self.parent_identity);
        assert_eq!((named.dev(), named.ino()), self.parent_identity);
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => panic!("{e}"),
            Ok(m) => {
                assert_eq!((m.dev(), m.ino()), self.identity);
                let fd = rustix::fs::openat(
                    &self.file,
                    "cgroup.events",
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .unwrap();
                let mut bytes = String::new();
                File::from(fd)
                    .take(4097)
                    .read_to_string(&mut bytes)
                    .unwrap();
                assert!(bytes.len() <= 4096);
                assert_eq!(
                    bytes
                        .lines()
                        .filter(|l| l.starts_with("populated "))
                        .count(),
                    1
                );
                bytes.lines().any(|l| l == "populated 0")
            }
        }
    }
}
