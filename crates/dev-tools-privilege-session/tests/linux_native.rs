#![cfg(target_os = "linux")]
//! Explicit root-only acceptance of the shared native mechanism. This harness
//! grants no caller authority and is not a substitute for product/approval tests.

use dev_tools_privilege_session::linux::{boot_time, ExecutionBoundary, NativeContext};
use nix::fcntl::OFlag;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn parent() -> File {
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "explicit native acceptance requires root"
    );
    let own = File::open("/proc/self/ns/user")
        .unwrap()
        .metadata()
        .unwrap();
    let init = File::open("/proc/1/ns/user").unwrap().metadata().unwrap();
    assert_eq!(
        (own.dev(), own.ino()),
        (init.dev(), init.ino()),
        "acceptance must exercise host authority"
    );
    let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap();
    let suffix = path
        .strip_prefix("/system.slice/dev-tools-privilege-accept-")
        .and_then(|tail| tail.strip_suffix(".service"))
        .expect("run only in an explicitly owned transient acceptance service");
    assert_eq!(suffix.len(), 32);
    assert!(suffix
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    File::open(format!("/sys/fs/cgroup{path}")).unwrap()
}

fn context(uid: u32) -> NativeContext {
    NativeContext {
        working_directory: File::open("/").unwrap(),
        mount_namespace: None,
        uid,
        effective_uid: uid,
        gid: uid,
        supplementary_groups: vec![],
        controlling_terminal: false,
        inherited_files: vec![],
    }
}

fn null_streams() -> [OwnedFd; 3] {
    std::array::from_fn(|_| {
        File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into()
    })
}

fn pidfd(pid: u32) -> OwnedFd {
    // SAFETY: pidfd_open returns one new owned descriptor or an error. The
    // fixture obtains each PID directly from its own newly spawned child.
    let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn alive(fd: &OwnedFd) -> bool {
    let mut events = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    poll(&mut events, PollTimeout::ZERO).unwrap() == 0
}

fn stopped(boundary: &mut ExecutionBoundary, leader: &mut Child, descendants: &[OwnedFd]) {
    boundary.stop().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if leader.try_wait().unwrap().is_some()
            && descendants.iter().all(|fd| !alive(fd))
            && boundary.is_empty().unwrap()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native descendants did not terminate"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    boundary.remove().unwrap();
}

#[test]
#[ignore = "requires explicit native root acceptance in an owned transient system service"]
fn cgroup_enforcement() {
    let parent = parent();
    let deadline = boot_time().unwrap() + Duration::from_secs(60);
    let mut identity =
        ExecutionBoundary::create(&parent, "retained-effective-identity", deadline).unwrap();
    let mut selected_identity = context(65534);
    selected_identity.effective_uid = 0;
    let held_image = File::open(std::env::current_exe().unwrap()).unwrap();
    let inherited: OwnedFd = File::open("/dev/null").unwrap().into();
    let mapped_fd = inherited.as_raw_fd();
    selected_identity.inherited_files = vec![inherited];
    let mut identity_child = identity
        .permit(vec![])
        .unwrap()
        .spawn_held(
            held_image,
            "native-identity-fixture".as_ref(),
            &[
                "--ignored".into(),
                "--exact".into(),
                "native_identity_child".into(),
            ],
            &[
                ("DEV_TOOLS_PRIVILEGE_NATIVE_CHILD".into(), "identity".into()),
                (
                    "DEV_TOOLS_PRIVILEGE_MAPPED_FD".into(),
                    mapped_fd.to_string().into(),
                ),
            ],
            selected_identity,
            null_streams(),
        )
        .unwrap();
    let identity_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = identity_child.try_wait().unwrap() {
            assert!(
                status.success(),
                "held ELF did not preserve real/effective identity"
            );
            break;
        }
        assert!(Instant::now() < identity_deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    identity.stop().unwrap();
    identity.remove().unwrap();
    let mut ordinary = ExecutionBoundary::create(&parent, "ordinary-sentinel", deadline).unwrap();
    let mut sentinel = ordinary
        .permit(vec![])
        .unwrap()
        .spawn(
            "/usr/bin/sleep".as_ref(),
            &["60".into()],
            &[],
            context(65534),
            null_streams(),
        )
        .unwrap();
    let sentinel_fd = pidfd(sentinel.id());
    let mut grant = ExecutionBoundary::create(&parent, "privileged-descendants", deadline).unwrap();
    let (read, write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    let mut streams = null_streams();
    streams[1] = write;
    let executable = std::env::current_exe().unwrap();
    let mut child = grant
        .permit(vec![pidfd(std::process::id())])
        .unwrap()
        .spawn(
            executable.as_os_str(),
            &[
                "--ignored".into(),
                "--exact".into(),
                "native_tree_child".into(),
                "--nocapture".into(),
            ],
            &[("DEV_TOOLS_PRIVILEGE_NATIVE_CHILD".into(), "tree".into())],
            context(0),
            streams,
        )
        .unwrap();
    let leader_fd = pidfd(child.id());
    let mut text = Vec::new();
    let mut read_file = File::from(read);
    let ready_by = Instant::now() + Duration::from_secs(5);
    let descendant = loop {
        assert!(
            Instant::now() < ready_by,
            "fixture descendant did not announce readiness"
        );
        let mut events = [PollFd::new(read_file.as_fd(), PollFlags::POLLIN)];
        if poll(&mut events, 100_u16).unwrap() == 0 {
            continue;
        }
        let mut bytes = [0; 1024];
        let length = read_file.read(&mut bytes).unwrap();
        assert!(length > 0 && text.len() + length <= 4096);
        text.extend_from_slice(&bytes[..length]);
        if let Some(pid) = String::from_utf8_lossy(&text).lines().find_map(|line| {
            line.strip_prefix("DESCENDANT ")
                .and_then(|value| value.parse::<u32>().ok())
        }) {
            break pid;
        }
    };
    let descendant_fd = pidfd(descendant);
    assert!(alive(&leader_fd) && alive(&descendant_fd));
    let expected = format!("/proc/self/fd/{}", grant.directory().as_raw_fd());
    let directory = std::fs::read_link(expected).unwrap();
    for pid in [child.id(), descendant] {
        let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        assert!(membership
            .lines()
            .any(|line| line
                .strip_prefix("0::")
                .is_some_and(|path| std::path::Path::new("/sys/fs/cgroup")
                    .join(path.trim_start_matches('/'))
                    == directory)));
    }
    stopped(&mut grant, &mut child, &[leader_fd, descendant_fd]);
    assert!(
        alive(&sentinel_fd),
        "revoking privilege must preserve the ordinary workload"
    );
    assert!(sentinel.try_wait().unwrap().is_none());

    let mut race = ExecutionBoundary::create(&parent, "prepared-before-revoke", deadline).unwrap();
    let permit = race.permit(vec![]).unwrap();
    race.stop().unwrap();
    assert!(
        permit
            .spawn(
                "/usr/bin/true".as_ref(),
                &[],
                &[],
                context(0),
                null_streams()
            )
            .is_err(),
        "an inherited prepared permit cannot enter after revocation"
    );
    assert!(race.is_empty().unwrap());
    race.remove().unwrap();

    let mut expiry = ExecutionBoundary::create(
        &parent,
        "expired-before-spawn",
        boot_time().unwrap() + Duration::from_millis(150),
    )
    .unwrap();
    let permit = expiry.permit(vec![]).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        permit
            .spawn(
                "/usr/bin/true".as_ref(),
                &[],
                &[],
                context(0),
                null_streams()
            )
            .is_err(),
        "hard expiry must deny an already prepared spawn"
    );
    expiry.stop().unwrap();
    expiry.remove().unwrap();

    let mut expiry = ExecutionBoundary::create(
        &parent,
        "live-hard-expiry",
        boot_time().unwrap() + Duration::from_millis(250),
    )
    .unwrap();
    let mut expiring = expiry
        .permit(vec![])
        .unwrap()
        .spawn(
            "/usr/bin/sleep".as_ref(),
            &["60".into()],
            &[],
            context(0),
            null_streams(),
        )
        .unwrap();
    let expiring_fd = pidfd(expiring.id());
    // No product tick, registry poll, stop call or request actor participates.
    // The independent native guard must enforce this live process's deadline.
    let observed_by = Instant::now() + Duration::from_secs(3);
    while alive(&expiring_fd) {
        assert!(
            Instant::now() < observed_by,
            "a stalled coordinator must not postpone hard expiry"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!expiring.wait().unwrap().success());
    assert!(expiry.is_empty().unwrap());
    expiry.stop().unwrap();
    expiry.remove().unwrap();
    assert!(alive(&sentinel_fd));
    stopped(&mut ordinary, &mut sentinel, &[sentinel_fd]);
}

#[test]
#[ignore = "private descendant fixture, invoked only by cgroup_enforcement"]
fn native_tree_child() {
    assert_eq!(
        std::env::var("DEV_TOOLS_PRIVILEGE_NATIVE_CHILD").as_deref(),
        Ok("tree")
    );
    assert!(nix::unistd::Uid::effective().is_root());
    let mut descendant = Command::new("/usr/bin/setsid")
        .args(["/usr/bin/sleep", "60"])
        .spawn()
        .unwrap();
    println!("\nDESCENDANT {}", descendant.id());
    std::io::stdout().flush().unwrap();
    let _ = descendant.wait();
}

#[test]
#[ignore = "private identity fixture, invoked only by cgroup_enforcement"]
fn native_identity_child() {
    assert_eq!(
        std::env::var("DEV_TOOLS_PRIVILEGE_NATIVE_CHILD").as_deref(),
        Ok("identity")
    );
    assert_eq!(nix::unistd::getuid().as_raw(), 65534);
    assert!(nix::unistd::geteuid().is_root());
    assert_eq!(nix::unistd::getgid().as_raw(), 65534);
    assert_eq!(nix::unistd::getegid().as_raw(), 65534);
    let mapped = std::env::var("DEV_TOOLS_PRIVILEGE_MAPPED_FD")
        .unwrap()
        .parse::<i32>()
        .unwrap();
    // SAFETY: the root fixture supplies this exact inherited descriptor; the
    // borrow remains local and does not create another owning handle.
    let descriptor = unsafe { std::os::fd::BorrowedFd::borrow_raw(mapped) };
    let mut byte = [0_u8];
    assert_eq!(nix::unistd::read(descriptor, &mut byte).unwrap(), 0);
}
