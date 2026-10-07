#![cfg(target_os = "linux")]

use dev_tools_privilege_session::native_linux::{
    ChildStatus, NativeError, RetainedCgroupDomain, ValidatedCgroupBoundary,
};
use std::ffi::OsStr;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OPT_IN: &str = "PRIVILEGE_SESSION_NATIVE_FIXTURE";
const MARKER: &str = "/run/privilege-session-native-fixture";
const MARKER_CONTENT: &str =
    "disposable-rootful-systemd-v1\nprivate-cgroups-no-host-mounts-no-secrets\n";
const FIXTURE_ROOT: &str = "/sys/fs/cgroup/privilege-session-native-fixture";
const WAIT: Duration = Duration::from_secs(5);

#[test]
fn ordinary_files_cannot_forge_a_kernel_boundary() {
    let fake = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("cgroup.type", "domain\n"),
        ("cgroup.events", "populated 0\nfrozen 0\n"),
        ("cgroup.procs", ""),
        ("cgroup.threads", ""),
        ("cgroup.subtree_control", ""),
        ("cgroup.kill", ""),
    ] {
        fs::write(fake.path().join(name), bytes).unwrap();
        fs::set_permissions(fake.path().join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::set_permissions(fake.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ValidatedCgroupBoundary::open(fake.path()).is_err());
    assert_eq!(fs::read(fake.path().join("cgroup.kill")).unwrap(), b"");
}

#[test]
fn relative_traversal_and_lexical_aliases_are_not_boundary_authority() {
    for path in [
        "relative",
        "../cgroup",
        "/tmp/../sys/fs/cgroup",
        "/sys//fs/cgroup",
        "/sys/./fs/cgroup",
        "/sys/fs/cgroup/",
    ] {
        assert!(matches!(
            ValidatedCgroupBoundary::open(Path::new(path)),
            Err(NativeError::InvalidPath)
        ));
    }
}

#[test]
fn symlink_and_writable_fixture_paths_are_rejected_without_mutation() {
    let fake = tempfile::tempdir().unwrap();
    let child = fake.path().join("child");
    fs::create_dir(&child).unwrap();
    let alias = fake.path().join("alias");
    std::os::unix::fs::symlink(&child, &alias).unwrap();
    assert!(ValidatedCgroupBoundary::open(&alias).is_err());
    fs::set_permissions(&child, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ValidatedCgroupBoundary::open(&child).is_err());
    assert!(fs::read_dir(child).unwrap().next().is_none());
}

// MUTATING NATIVE TESTS, NEVER RUN ON A LIVE HOST.
// The external runner must create an owned disposable ROOTFUL systemd container
// with private cgroup/PID/mount namespaces, no host mounts, no network or secrets,
// and an OUTSIDE timeout/destructor that destroys the entire container on failure.
// Inside that container only, the runner must create the root:root 0600 regular
// MARKER with exactly MARKER_CONTENT, create the root:root nondelegated empty
// FIXTURE_ROOT cgroup, then set OPT_IN=disposable-rootful-systemd-v1.
// An environment variable alone is insufficient. The marker is an explicit
// operator assertion of isolation; these tests cannot establish host isolation
// themselves and are not the product's independent deadline/crash acceptance.
// Select individual tests by --exact --ignored. Do not run a broad --ignored
// suite on a host and do not point the fixture at arbitrary existing cgroups.

fn require_disposable_fixture() -> ValidatedCgroupBoundary {
    assert_eq!(
        std::env::var(OPT_IN).as_deref(),
        Ok("disposable-rootful-systemd-v1"),
        "native fixture requires explicit disposable opt-in"
    );
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let container = fs::read_to_string("/run/systemd/container")
        .expect("systemd container marker is mandatory");
    assert!(
        matches!(
            container.trim(),
            "docker" | "podman" | "systemd-nspawn" | "nspawn"
        ),
        "unknown or host environment"
    );
    for path in ["/proc/self/uid_map", "/proc/self/gid_map"] {
        let mapping = fs::read_to_string(path).unwrap();
        let words: Vec<_> = mapping.split_whitespace().collect();
        assert_eq!(
            words,
            ["0", "0", "4294967295"],
            "fixture must be rootful, without UID/GID remapping"
        );
    }
    let metadata =
        fs::symlink_metadata(MARKER).expect("explicit root-owned isolation marker is mandatory");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), 0);
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(MARKER).unwrap(), MARKER_CONTENT);
    let boundary = ValidatedCgroupBoundary::open(Path::new(FIXTURE_ROOT)).unwrap();
    assert_eq!(
        fs::read_to_string(Path::new(FIXTURE_ROOT).join("cgroup.procs")).unwrap(),
        "",
        "synthetic boundary must contain no coordinator or unrelated processes"
    );
    boundary
}

fn domain(boundary: &ValidatedCgroupBoundary, case: &str) -> RetainedCgroupDomain {
    boundary
        .create_domain(OsStr::new(&format!(
            "synthetic-{case}-{}",
            std::process::id()
        )))
        .unwrap()
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("privilege-session-native-")
        .tempdir_in("/run")
        .unwrap()
}

fn payload(mode: &str, output: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "native_fixture_payload",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env(OPT_IN, "disposable-rootful-systemd-v1")
        .env("PRIVILEGE_SESSION_PAYLOAD_MODE", mode)
        .env("PRIVILEGE_SESSION_PAYLOAD_OUTPUT", output)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < WAIT,
            "native fixture observation timed out"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "mutating: explicit disposable rootful systemd/private-cgroup fixture only"]
fn native_gate_precedes_exec_and_repeated_children_reuse_the_owned_domain() {
    let boundary = require_disposable_fixture();
    let scratch = scratch();
    let mut domain = domain(&boundary, "reuse");
    assert!(boundary
        .create_domain(domain.path().file_name().unwrap())
        .is_err());
    for index in 0..3 {
        let output = scratch.path().join(format!("effect-{index}"));
        let child = domain
            .spawn_gated(payload("write-once", &output), WAIT)
            .unwrap();
        assert_eq!(domain.child_status(child).unwrap(), ChildStatus::Gated);
        thread::sleep(Duration::from_millis(30));
        assert!(!output.exists(), "payload ran before the gate was released");
        domain.release_child(child).unwrap();
        assert!(
            domain.release_child(child).is_err(),
            "one gate cannot be released twice"
        );
        wait_until(|| matches!(domain.child_status(child).unwrap(), ChildStatus::Exited(_)));
        assert_eq!(fs::read(output).unwrap(), b"synthetic-effect\n");
    }
    let proof = domain.terminate(WAIT).unwrap();
    assert_eq!(proof.joined_children(), 3);
    assert!(!proof.had_prior_failure());
    assert!(!domain.populated().unwrap());
    domain.remove().unwrap();
}

#[test]
#[ignore = "mutating: explicit disposable rootful systemd/private-cgroup fixture only"]
fn native_revoke_aborts_unreleased_gate_and_preserves_cleanup_failure_history() {
    let boundary = require_disposable_fixture();
    let scratch = scratch();
    let output = scratch.path().join("never-executed");
    let mut domain = domain(&boundary, "abort");
    let child = domain
        .spawn_gated(payload("write-once", &output), WAIT)
        .unwrap();
    assert!(domain.terminate(Duration::ZERO).is_err());
    assert!(matches!(
        domain.release_child(child),
        Err(NativeError::AdmissionClosed)
    ));
    let proof = domain.terminate(WAIT).unwrap();
    assert!(proof.had_prior_failure());
    assert_eq!(proof.joined_children(), 1);
    assert!(!output.exists());
    domain.remove().unwrap();
}

#[test]
#[ignore = "mutating: explicit disposable rootful systemd/private-cgroup fixture only"]
fn native_leader_exit_is_not_cleanup_and_kill_covers_double_fork_setsid_descendant() {
    let boundary = require_disposable_fixture();
    let scratch = scratch();
    let output = scratch.path().join("protected-writes");
    let mut domain = domain(&boundary, "descendants");
    let child = domain
        .spawn_gated(payload("double-fork", &output), WAIT)
        .unwrap();
    domain.release_child(child).unwrap();
    wait_until(|| matches!(domain.child_status(child).unwrap(), ChildStatus::Exited(_)));
    wait_until(|| fs::metadata(&output).is_ok_and(|metadata| metadata.len() > 2));
    assert!(
        domain.populated().unwrap(),
        "detached descendant must outlive its direct leader"
    );
    assert!(matches!(
        domain.remove(),
        Err(NativeError::CleanupNotComplete)
    ));
    domain.terminate(WAIT).unwrap();
    let size = fs::metadata(&output).unwrap().len();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        fs::metadata(&output).unwrap().len(),
        size,
        "protected writes survived cleanup"
    );
    assert!(!domain.populated().unwrap());
    domain.remove().unwrap();
}

#[test]
#[ignore = "mutating: explicit disposable rootful systemd/private-cgroup fixture only"]
fn native_socket_peer_requires_live_pidfd_owner_and_exact_domain_membership() {
    let boundary = require_disposable_fixture();
    let scratch = scratch();
    let socket = scratch.path().join("peer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut domain = domain(&boundary, "peer");
    let (outside, _other) = UnixStream::pair().unwrap();
    assert!(domain.authenticate_peer(&outside, 0, 0).is_err());
    let child = domain.spawn_gated(payload("peer", &socket), WAIT).unwrap();
    domain.release_child(child).unwrap();
    let mut accepted = None;
    wait_until(|| match listener.accept() {
        Ok((stream, _)) => {
            accepted = Some(stream);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("accept fixture peer: {error}"),
    });
    let stream = accepted.unwrap();
    assert!(domain.authenticate_peer(&stream, 1, 0).is_err());
    let peer = domain.authenticate_peer(&stream, 0, 0).unwrap();
    assert!(peer.is_alive().unwrap());
    domain.revalidate_peer(&peer).unwrap();
    domain.terminate(WAIT).unwrap();
    assert!(!peer.is_alive().unwrap());
    assert!(domain.revalidate_peer(&peer).is_err());
    domain.remove().unwrap();
}

#[test]
#[ignore = "mutating: explicit disposable rootful systemd/private-cgroup fixture only"]
fn native_replacement_and_delegated_membership_fail_closed_without_killing_a_foreign_domain() {
    let boundary = require_disposable_fixture();
    let scratch = scratch();
    let mut original = domain(&boundary, "identity");
    let original_path = original.path().to_owned();
    let moved_path =
        original_path.with_file_name(format!("synthetic-moved-{}", std::process::id()));
    fs::rename(&original_path, &moved_path).unwrap();
    let mut replacement = boundary
        .create_domain(original_path.file_name().unwrap())
        .unwrap();
    let output = scratch.path().join("replacement-writes");
    let child = replacement
        .spawn_gated(payload("double-fork", &output), WAIT)
        .unwrap();
    replacement.release_child(child).unwrap();
    wait_until(|| fs::metadata(&output).is_ok_and(|metadata| metadata.len() > 2));
    assert!(original.validate().is_err());
    assert!(original.terminate(WAIT).is_err());
    assert!(
        replacement.populated().unwrap(),
        "stale path must not kill its foreign replacement"
    );
    replacement.terminate(WAIT).unwrap();
    replacement.remove().unwrap();
    fs::rename(&moved_path, &original_path).unwrap();
    original.validate().unwrap();
    let membership = original_path.join("cgroup.procs");
    let mode = fs::metadata(&membership).unwrap().mode() & 0o777;
    fs::set_permissions(&membership, fs::Permissions::from_mode(mode | 0o020)).unwrap();
    assert!(
        original.validate().is_err(),
        "delegated membership must invalidate the domain"
    );
    fs::set_permissions(&membership, fs::Permissions::from_mode(mode)).unwrap();
    let proof = original.terminate(WAIT).unwrap();
    assert!(proof.had_prior_failure());
    original.remove().unwrap();
}

#[test]
#[ignore = "helper selected only by the opted-in disposable native tests"]
fn native_fixture_payload() {
    let Ok(mode) = std::env::var("PRIVILEGE_SESSION_PAYLOAD_MODE") else {
        return;
    };
    // Recheck isolation before any fixture effect, even in the gated child.
    let _boundary = require_disposable_fixture();
    let output = PathBuf::from(std::env::var_os("PRIVILEGE_SESSION_PAYLOAD_OUTPUT").unwrap());
    let parent = output.parent().unwrap();
    assert_eq!(parent.parent(), Some(Path::new("/run")));
    assert!(parent
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("privilege-session-native-"));
    assert_eq!(fs::symlink_metadata(parent).unwrap().uid(), 0);
    match mode.as_str() {
        "write-once" => fs::write(output, b"synthetic-effect\n").unwrap(),
        "peer" => {
            let _socket = UnixStream::connect(output).unwrap();
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        "double-fork" => {
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .unwrap();
            let fd = file.as_raw_fd();
            // SAFETY: native-fixture-only fork children perform async-signal-safe
            // operations and _exit without unwinding through the test harness.
            unsafe {
                let child = libc::fork();
                assert!(child >= 0);
                if child == 0 {
                    if libc::setsid() < 0 {
                        libc::_exit(2);
                    }
                    let detached = libc::fork();
                    if detached < 0 {
                        libc::_exit(3);
                    }
                    if detached > 0 {
                        libc::_exit(0);
                    }
                    libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    let pause = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 5_000_000,
                    };
                    loop {
                        if libc::write(fd, b"x".as_ptr().cast(), 1) != 1 {
                            libc::_exit(4);
                        }
                        libc::nanosleep(&pause, std::ptr::null_mut());
                    }
                }
                let mut status = 0;
                assert_eq!(libc::waitpid(child, &mut status, 0), child);
                assert_eq!(status, 0);
            }
        }
        _ => panic!("unknown native fixture payload"),
    }
}
