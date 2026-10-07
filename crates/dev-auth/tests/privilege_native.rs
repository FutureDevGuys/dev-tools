#![cfg(all(target_os = "linux", feature = "native-privilege-fixture"))]
//! Opt-in public native acceptance. These tests never install policy, create
//! accounts, supply credentials, or configure unattended administrator approval.
#[path = "support/privilege_native_contract.rs"]
mod contract;
use contract::{Case, Input};
use dev_auth::privilege::{policy, protocol, runtime};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

#[test]
fn kernel_boot_deadline_kills_even_a_stopped_coordinator_process() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dev-auth-privilege-native-fixture"))
        .arg("timer-stop")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = match child.wait_timeout(Duration::from_secs(3)).unwrap() {
        Some(status) => status,
        None => {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("independent deadline did not terminate stopped process");
        }
    };
    assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
}

#[test]
fn native_matrix_inputs_are_closed_and_case_names_are_finite() {
    for case in [
        Case::Reuse,
        Case::Revoke,
        Case::HardExpiry,
        Case::IdleExpiry,
        Case::NearIdleAdmission,
        Case::CoordinatorDeath,
        Case::BootstrapDeath,
        Case::HandoffBootstrapDeath,
        Case::ControllerGateBootstrapDeath,
        Case::GuardianDeath,
        Case::MalformedIpc,
        Case::IdentityDenial,
        Case::PolicyReplaced,
        Case::HelperReplaced,
        Case::ResourceReplaced,
        Case::Busy,
        Case::Replay,
        Case::Exhaustion,
        Case::BlockedIo,
        Case::SetupExclusion,
        Case::CleanupFailure,
        Case::SignalFidelity,
        Case::LeaderExit,
        Case::NestedResourceMount,
        Case::CoreCollector,
        Case::CoreCoordinatorDeath,
        Case::CoreBootstrapDeath,
    ] {
        assert_eq!(
            serde_json::from_value::<Case>(serde_json::json!(case.name())).unwrap(),
            case
        );
    }
    assert!(serde_json::from_str::<Case>("\"arbitrary-root-command\"").is_err());
    let input = serde_json::json!({"schema":"dev-auth-privilege-native-input-v1", "dev_auth":"/a", "fixture_binary":"/b",
        "fixture_root":"/var/tmp/dev-auth-privilege-native-test", "approval_plan":"/c", "approval_sha256":"0".repeat(64), "case":"reuse", "command":"anything"});
    assert!(serde_json::from_value::<Input>(input).is_err());
}

#[test]
fn root_fault_injector_cannot_run_without_explicit_disposable_opt_in() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth-privilege-native-fixture"))
        .args(["fault-driver", "/nonexistent-native-fault-input.json"])
        .env_remove("DEV_AUTH_NATIVE_PRIVILEGE_FAULTS")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"native privilege fixture failed\n");
}
#[test]
fn fixture_preparation_rejects_non_disposable_roots_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth-privilege-native-fixture"))
        .args([
            "prepare",
            "reuse",
            "/usr/local/bin/dev-auth",
            "/usr/local/lib/dev-auth-native-fixture",
        ])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

fn require_input() -> (Input, policy::ApprovalPlan) {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_PRIVILEGE_FIXTURE").as_deref(),
        Ok("disposable")
    );
    let uid = unsafe { nix::libc::getuid() };
    assert_ne!(uid, 0, "observer must remain the native non-root user");
    assert_eq!(unsafe { nix::libc::geteuid() }, uid);
    assert!(
        Path::new("/run/.containerenv").is_file(),
        "never run the native matrix on a host"
    );
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    assert!(Path::new("/sys/fs/cgroup/cgroup.controllers").is_file());
    let path = PathBuf::from(
        std::env::var_os("DEV_AUTH_NATIVE_PRIVILEGE_INPUT")
            .expect("explicit private input required"),
    );
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert!(metadata.len() < 64 * 1024);
    let input: Input = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(input.schema, "dev-auth-privilege-native-input-v1");
    assert_eq!(input.fixture_root.parent(), Some(Path::new("/var/tmp")));
    assert!(input
        .fixture_root
        .components()
        .all(|c| matches!(c, Component::RootDir | Component::Normal(_))));
    assert!(input
        .fixture_root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("dev-auth-privilege-native-"));
    let root = fs::symlink_metadata(&input.fixture_root).unwrap();
    assert!(root.is_dir() && !root.file_type().is_symlink());
    assert_eq!(root.uid(), uid);
    assert_eq!(root.mode() & 0o7777, 0o700);
    let scope = input.fixture_root.join("scope");
    let scope_meta =
        fs::symlink_metadata(&scope).expect("pre-created caller-owned mode-0700 scope required");
    assert!(scope_meta.is_dir());
    assert_eq!(scope_meta.uid(), uid);
    assert_eq!(scope_meta.mode() & 0o7777, 0o700);
    if input.case == Case::NestedResourceMount {
        let leaves = fs::read_dir(&scope)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            leaves,
            [std::ffi::OsString::from("nested")],
            "only the prepared nested sentinel fixture is allowed"
        );
    } else {
        assert_eq!(
            fs::read_dir(&scope).unwrap().count(),
            0,
            "fresh scope required"
        );
    }
    for leaf in [
        "session",
        "controller-passed",
        "fault-applied",
        "fault-driver-passed",
        "identity-tested",
        "exhausted",
        "io-blocked",
        "observer-held",
        "near-idle-passed",
        "frontend-pid",
        "handoff-prepared",
        "observer-cleanup",
    ] {
        assert!(
            !input.fixture_root.join(leaf).exists(),
            "fresh fixture required"
        );
    }
    let bytes = fs::read(&input.approval_plan).unwrap();
    assert_eq!(policy::digest(&bytes), input.approval_sha256);
    let approval: policy::ApprovalPlan = policy::parse(&bytes).unwrap();
    assert_eq!(policy::canonical(&approval).unwrap(), bytes);
    assert_eq!(approval.request.owner_uid, uid);
    assert!(
        (2..=60).contains(&approval.request.hard_seconds),
        "fixture hard lifetime must be at most sixty seconds"
    );
    assert!(approval.request.idle_seconds <= approval.request.hard_seconds);
    assert_eq!(approval.operations.len(), 1);
    let operation = approval
        .operations
        .get("fixture")
        .expect("fixture operation required");
    for (id, plan) in &operation.plans {
        assert_eq!(PathBuf::from(&plan.executable), input.fixture_binary);
        assert_eq!(
            policy::digest(&fs::read(&input.fixture_binary).unwrap()),
            plan.executable_sha256
        );
        assert_eq!(
            plan.resources.len(),
            1,
            "only the disposable scope may be mounted"
        );
        assert!(plan
            .resources
            .values()
            .all(|r| Path::new(&r.path) == scope && r.access == policy::Access::ReadWrite));
        let (action, leaf) = match id.as_str() {
            "write-a" => ("write", "a"),
            "write-b" => ("write", "b"),
            "probe" => ("probe", "probe"),
            "core-probe" => ("core-probe", "core"),
            "detached" => ("detached", "heartbeat"),
            "leader-exit" => ("leader-exit", "leader-heartbeat"),
            "nested-probe" => ("nested-probe", "nested"),
            "hold" => ("hold", "hold"),
            "streams" => ("streams", "unused"),
            "blocked-output" => ("blocked-output", "output"),
            "signal-term" => ("signal-term", "unused"),
            "signal-segv" => ("signal-segv", "unused"),
            _ => panic!("native fixture plan is outside the closed subject set"),
        };
        assert_eq!(
            plan.arguments,
            vec![
                b"helper".to_vec(),
                action.as_bytes().to_vec(),
                scope.join(leaf).as_os_str().as_encoded_bytes().to_vec()
            ]
        );
        assert!(plan.environment.is_empty());
        assert_eq!(Path::new(&plan.working_directory), scope);
        if id == "streams" {
            assert_eq!(plan.input, [0, 255, 10, 13, 128]);
        } else {
            assert!(plan.input.is_empty());
        }
    }
    let needed: &[&str] = match input.case {
        Case::Reuse => &["write-a", "write-b", "probe"],
        Case::Busy => &["hold", "write-a"],
        Case::NearIdleAdmission => &["hold"],
        Case::LeaderExit => &["leader-exit", "write-a"],
        Case::NestedResourceMount => &["nested-probe", "write-a"],
        Case::Replay | Case::Exhaustion => &["write-a", "write-b"],
        Case::SignalFidelity => &["streams", "signal-term", "signal-segv"],
        Case::CoreCollector => &["core-probe"],
        Case::BlockedIo => &["blocked-output", "detached"],
        case if case.needs_heartbeat() => &["detached"],
        _ => &["write-a"],
    };
    for plan in needed {
        assert!(
            operation.plans.contains_key(*plan),
            "required fixture plan absent"
        );
    }
    if input.case == Case::MalformedIpc {
        assert!(approval.request.idle_seconds >= 15);
    }
    if matches!(input.case, Case::IdleExpiry | Case::NearIdleAdmission) {
        assert!(approval.request.idle_seconds + 3 < approval.request.hard_seconds);
    }
    if input.case == Case::HardExpiry {
        assert_eq!(approval.request.idle_seconds, approval.request.hard_seconds);
    }
    if input.case.completes_normally() {
        assert!(approval.request.total_uses >= 5 && operation.max_uses >= 5);
    }
    if input.case == Case::Exhaustion {
        assert!(approval.request.total_uses <= 8 && operation.max_uses <= 8);
    }
    if input.case.needs_fault_driver() {
        let ready = input.fixture_root.join("fault-driver-ready");
        assert_eq!(
            fs::symlink_metadata(&ready)
                .expect("start the explicitly approved root fixture driver first")
                .uid(),
            0
        );
        assert_eq!(fs::read_to_string(ready).unwrap(), input.case.name());
    }
    let pattern = fs::read("/proc/sys/kernel/core_pattern").unwrap();
    assert!(
        native_core_pattern_allowed(input.case, &pattern),
        "native case/core profile mismatch"
    );
    if is_collector_case(input.case) {
        assert_eq!(
            std::env::var("DEV_AUTH_NATIVE_CORE_GUEST").as_deref(),
            Ok("disposable-qemu")
        );
        let vm = Command::new("/usr/bin/systemd-detect-virt")
            .arg("--vm")
            .output()
            .unwrap();
        assert!(vm.status.success() && matches!(vm.stdout.as_slice(), b"qemu\n" | b"kvm\n"));
        let marker = fs::symlink_metadata("/run/dev-auth-qualification-auth").unwrap();
        assert!(marker.is_file() && marker.uid() == 0 && marker.mode() & 0o022 == 0);
        assert_eq!(
            fs::read("/run/dev-auth-qualification-auth").unwrap(),
            fs::read("/proc/sys/kernel/random/boot_id").unwrap()
        );
        assert_eq!(
            fs::read_dir("/sys/class/net")
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [std::ffi::OsString::from("lo")]
        );
        let collector = Path::new("/usr/libexec/dev-auth-core-collector");
        dev_auth::privilege::custody::held_root_executable(
            collector,
            &policy::digest(&fs::read(&input.fixture_binary).unwrap()),
        )
        .expect("collector must be the exact independently root-custodied fixture image");
        let driver = fs::metadata(&input.fixture_binary).unwrap();
        let image = fs::metadata(collector).unwrap();
        assert_ne!(
            (driver.dev(), driver.ino()),
            (image.dev(), image.ino()),
            "dedicated collector inode required"
        );
    }
    (input, approval)
}
fn is_collector_case(case: Case) -> bool {
    matches!(
        case,
        Case::CoreCollector | Case::CoreCoordinatorDeath | Case::CoreBootstrapDeath
    )
}
fn native_core_pattern_allowed(case: Case, pattern: &[u8]) -> bool {
    if is_collector_case(case) {
        pattern == b"|/usr/libexec/dev-auth-core-collector core-collector %P\n"
    } else {
        let value = pattern.strip_suffix(b"\n").unwrap_or(pattern);
        !value.starts_with(b"|")
            && !value.starts_with(b"@")
            && !value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    }
}
#[test]
fn collector_profile_is_restricted_to_exact_core_cases() {
    let pipe = b"|/usr/libexec/dev-auth-core-collector core-collector %P\n";
    for case in [
        Case::CoreCollector,
        Case::CoreCoordinatorDeath,
        Case::CoreBootstrapDeath,
    ] {
        assert!(native_core_pattern_allowed(case, pipe));
        for wrong in [
            b"core\n".as_slice(),
            b"|/usr/bin/other %P\n",
            b"@/collector\n",
            b"|/usr/libexec/dev-auth-core-collector core-collector %p\n",
        ] {
            assert!(!native_core_pattern_allowed(case, wrong));
        }
    }
    for case in [Case::Reuse, Case::SignalFidelity, Case::CoordinatorDeath] {
        assert!(native_core_pattern_allowed(case, b"core\n"));
        assert!(!native_core_pattern_allowed(case, pipe));
        assert!(!native_core_pattern_allowed(case, b"@/collector\n"));
    }
}
fn wait_for(path: &Path, seconds: u64) {
    let until = Instant::now() + Duration::from_secs(seconds);
    while !path.exists() {
        assert!(
            Instant::now() < until,
            "fixture synchronization timed out: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn command(input: &Input, action: &str, session: &str) -> Command {
    let mut c = Command::new(&input.dev_auth);
    c.args(["privilege", action, "--session", session]);
    c
}

/// A read-only held observation, distinct from the product's own cleanup claim.
struct HeldDomain {
    path: PathBuf,
    file: File,
    identity: (u64, u64),
    parent: File,
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
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(path.parent().unwrap())
            .unwrap();
        let pm = parent.metadata().unwrap();
        Self {
            path,
            file,
            identity: (m.dev(), m.ino()),
            parent,
            parent_identity: (pm.dev(), pm.ino()),
        }
    }
    fn empty_or_removed(&self) -> bool {
        let held = self.file.metadata().unwrap();
        assert_eq!((held.dev(), held.ino()), self.identity);
        let parent_held = self.parent.metadata().unwrap();
        let parent_named = fs::symlink_metadata(self.path.parent().unwrap()).unwrap();
        assert_eq!((parent_held.dev(), parent_held.ino()), self.parent_identity);
        assert_eq!(
            (parent_named.dev(), parent_named.ino()),
            self.parent_identity
        );
        match fs::symlink_metadata(&self.path) {
            Ok(m) => {
                assert_eq!(
                    (m.dev(), m.ino()),
                    self.identity,
                    "guardian cgroup was replaced"
                );
                let fd = rustix::fs::openat(
                    &self.file,
                    "cgroup.events",
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .unwrap();
                let mut events = String::new();
                File::from(fd)
                    .take(4097)
                    .read_to_string(&mut events)
                    .unwrap();
                assert!(events.len() <= 4096);
                events
                    .lines()
                    .filter_map(|line| line.strip_prefix("populated "))
                    .collect::<Vec<_>>()
                    == ["0"]
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => panic!("guardian cleanup observation failed: {e}"),
        }
    }
}

#[test]
#[ignore = "requires explicitly prepared disposable rootful-systemd guest, installed candidate, real administrator approval and (for fault cases) separately authorized root fixture driver"]
fn public_reusable_session_approval_execution_and_terminal_cleanup() {
    let (input, approval) = require_input();
    let mut request = Command::new(&input.dev_auth)
        .args(["privilege", "request", "--plan"])
        .arg(&input.approval_plan)
        .args([
            "--sha256",
            &input.approval_sha256,
            "--authorize",
            "polkit",
            "--",
        ])
        .arg(&input.fixture_binary)
        .args(["controller", &input.case.name()])
        .arg(&input.dev_auth)
        .arg(&input.fixture_root)
        .arg(&input.approval_plan)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    fs::write(
        input.fixture_root.join("frontend-pid"),
        request.id().to_string(),
    )
    .unwrap();
    if matches!(
        input.case,
        Case::HandoffBootstrapDeath | Case::ControllerGateBootstrapDeath
    ) {
        observe_early_handoff(&input, &mut request, approval.request.hard_seconds);
        return;
    }
    let admission_deadline = Instant::now() + Duration::from_secs(125);
    let session = loop {
        if let Ok(value) = fs::read_to_string(input.fixture_root.join("session")) {
            if protocol::token(&value).is_ok() {
                break value;
            }
        }
        assert!(
            request.try_wait().unwrap().is_none(),
            "native approval/controller startup failed"
        );
        if Instant::now() >= admission_deadline {
            request.kill().unwrap();
            request.wait().unwrap();
            panic!("native approval not completed");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let started = Instant::now();
    let domain = HeldDomain::open(PathBuf::from(format!(
        "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
    )));
    fs::write(input.fixture_root.join("observer-held"), session.as_bytes()).unwrap();
    if input.case.needs_heartbeat() {
        let until = Instant::now() + Duration::from_secs(10);
        while fs::metadata(input.fixture_root.join("scope/heartbeat"))
            .map(|m| m.len())
            .unwrap_or(0)
            < 10
        {
            assert!(
                Instant::now() < until,
                "detached root descendant never produced evidence"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if input.case == Case::IdentityDenial {
        wait_for(&input.fixture_root.join("identity-ready"), 5);
        let denied = command(&input, "execute-plan", &session)
            .env("DEV_AUTH_PRIVILEGE_SESSION", &session)
            .env("SUDO_UID", "0")
            .env("PKEXEC_UID", "0")
            .args(["--operation", "fixture", "--plan-id", "write-a"])
            .output()
            .unwrap();
        assert_eq!(
            denied.status.code(),
            Some(4),
            "copied hints admitted an outside-controller peer"
        );
        assert!(!input.fixture_root.join("scope/a").exists());
        fs::write(input.fixture_root.join("identity-tested"), b"done").unwrap();
    }
    if input.case.needs_fault_driver() {
        wait_for(&input.fixture_root.join("fault-applied"), 10);
    }
    if input.case == Case::BlockedIo {
        wait_for(&input.fixture_root.join("io-blocked"), 10);
    }
    if matches!(
        input.case,
        Case::Revoke | Case::SetupExclusion | Case::CleanupFailure
    ) {
        let result = command(&input, "revoke", &session)
            .arg("--json")
            .output()
            .unwrap();
        if input.case == Case::CleanupFailure {
            assert!(
                !result.status.success(),
                "cleanup failure was converted to successful revoke"
            );
        } else {
            assert!(result.status.success(), "explicit revoke failed");
        }
    }
    let status = match request
        .wait_timeout(Duration::from_secs(approval.request.hard_seconds + 25))
        .unwrap()
    {
        Some(status) => status,
        None => {
            request.kill().unwrap();
            request.wait().unwrap();
            panic!("native session did not terminate");
        }
    };
    if input.case.completes_normally() {
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(input.fixture_root.join("controller-passed")).unwrap(),
            input.case.name()
        );
    }
    if input.case == Case::IdleExpiry {
        assert!(
            started.elapsed() < Duration::from_secs(approval.request.hard_seconds),
            "idle expiry waited for hard expiry"
        );
    }
    if input.case == Case::NearIdleAdmission {
        let bytes: [u8; 8] = fs::read(input.fixture_root.join("near-idle-passed"))
            .expect("near-idle operation did not survive original deadline")
            .try_into()
            .unwrap();
        let completion = u64::from_be_bytes(bytes);
        let now = dev_auth::linux_platform::boot_time_millis().unwrap();
        assert!(
            now >= completion + 1800,
            "accepted activity failed to renew idle expiry"
        );
        assert!(
            now < completion + 5000,
            "status polling postponed renewed idle expiry"
        );
    }
    let observation = command(&input, "status", &session)
        .arg("--json")
        .output()
        .unwrap();
    if input.case == Case::BootstrapDeath {
        assert!(
            !status.success(),
            "dead bootstrap claimed successful completion"
        );
        // No bootstrap remains to publish a final receipt. Unknown status is
        // permitted, but cannot substitute for the independent kernel proof.
        if let Ok(result) = serde_json::from_slice::<serde_json::Value>(&observation.stdout) {
            assert_ne!(result["outcome"], "completed");
        }
    } else {
        let result: serde_json::Value = serde_json::from_slice(&observation.stdout)
            .expect("authenticated terminal status required");
        if input.case != Case::CleanupFailure {
            assert_eq!(result["cleanup_complete"], true);
        }
        if input.case == Case::CleanupFailure {
            assert_eq!(result["outcome"], "failed");
            assert!(!status.success());
        }
    }
    let until = Instant::now() + Duration::from_secs(8);
    while !domain.empty_or_removed() {
        assert!(
            Instant::now() < until,
            "held guardian domain remains populated"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    while domain.path.exists() {
        assert!(
            Instant::now() < until,
            "guardian cgroup remains after terminal cleanup"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !runtime::socket_path(&session).unwrap().exists(),
        "stale control endpoint survived cleanup"
    );
    if input.case.needs_heartbeat() {
        let path = input.fixture_root.join("scope/heartbeat");
        let before = fs::metadata(&path).unwrap().len();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            fs::metadata(path).unwrap().len(),
            before,
            "privileged descendant wrote after cleanup"
        );
    }
    if input.case == Case::Exhaustion {
        let count = approval
            .request
            .total_uses
            .min(approval.operations["fixture"].max_uses);
        assert_eq!(
            fs::metadata(input.fixture_root.join("scope/a"))
                .unwrap()
                .len(),
            count * b"approved-root-effect\n".len() as u64
        );
        assert!(!input.fixture_root.join("scope/b").exists());
    }
    if input.case == Case::ResourceReplaced {
        assert_eq!(
            fs::read_dir(input.fixture_root.join("scope"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(input.fixture_root.join("scope-held"))
                .unwrap()
                .count(),
            0
        );
    }
    let denied = command(&input, "execute-plan", &session)
        .args(["--operation", "fixture", "--plan-id", "write-a"])
        .output()
        .unwrap();
    assert!(!denied.status.success(), "terminated grant was revived");
    fs::write(
        input.fixture_root.join("observer-cleanup"),
        session.as_bytes(),
    )
    .unwrap();
    if input.case.needs_fault_driver() {
        wait_for(&input.fixture_root.join("fault-driver-passed"), 10);
    }
}

fn observe_early_handoff(input: &Input, request: &mut std::process::Child, hard: u64) {
    let ready = input.fixture_root.join("handoff-prepared");
    let until = Instant::now() + Duration::from_secs(125);
    let session = loop {
        if let Ok(session) = fs::read_to_string(&ready) {
            if protocol::token(&session).is_ok() {
                assert_eq!(fs::symlink_metadata(&ready).unwrap().uid(), 0);
                break session;
            }
        }
        assert!(
            request.try_wait().unwrap().is_none(),
            "bootstrap ended before pinned handoff fault"
        );
        assert!(
            !input.fixture_root.join("session").exists(),
            "pre-controller handoff window was lost"
        );
        assert!(
            Instant::now() < until,
            "pre-controller handoff fixture timed out"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    let domain = HeldDomain::open(PathBuf::from(format!(
        "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
    )));
    assert_eq!(
        domain.path.join("controller").exists(),
        input.case == Case::ControllerGateBootstrapDeath,
        "controller domain differs from selected early handoff precondition"
    );
    fs::write(input.fixture_root.join("observer-held"), session.as_bytes()).unwrap();
    wait_for(&input.fixture_root.join("fault-applied"), 5);
    let status = request
        .wait_timeout(Duration::from_secs(hard + 20))
        .unwrap()
        .expect("killed bootstrap did not terminate frontend");
    assert!(
        !status.success(),
        "pre-controller bootstrap death claimed success"
    );
    wait_for(&input.fixture_root.join("fault-driver-passed"), hard + 20);
    assert!(
        domain.empty_or_removed(),
        "pre-controller fault left a populated native domain"
    );
    assert!(
        !domain.path.exists(),
        "pre-controller guardian unit remains"
    );
    assert!(
        !input.fixture_root.join("session").exists(),
        "controller gate released despite pre-controller fault"
    );
    assert_eq!(
        fs::read_dir(input.fixture_root.join("scope"))
            .unwrap()
            .count(),
        0,
        "pre-controller fault produced protected effects"
    );
    for leaf in ["control.sock", "handoff.sock"] {
        assert!(
            !runtime::session_directory(&session)
                .unwrap()
                .join(leaf)
                .exists(),
            "stale handoff endpoint survived cleanup"
        );
    }
    assert!(
        !command(input, "execute-plan", &session)
            .args(["--operation", "fixture", "--plan-id", "write-a"])
            .output()
            .unwrap()
            .status
            .success(),
        "failed handoff revived an executable grant"
    );
}

#[test]
fn core_limit_filter_survives_native_child_exec_and_rejects_writes() {
    let status = Command::new(env!("CARGO_BIN_EXE_dev-auth-privilege-native-fixture"))
        .arg("core-filter-selftest")
        .status()
        .unwrap();
    assert!(status.success());
}
