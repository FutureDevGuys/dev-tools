//! Finite root fault injector for an ALREADY authorized disposable guest only.
//! It is never installed, has no approval/policy bypass and accepts no commands.
#[path = "privilege_native_handoff.rs"]
mod handoff;
#[path = "privilege_native_nested.rs"]
mod nested;
use super::privilege_native_contract::{Case, Input};
use anyhow::{bail, Context, Result};
use dev_auth::privilege::{custody, policy, protocol};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn run(path: &Path) -> Result<()> {
    if std::env::var("DEV_AUTH_NATIVE_PRIVILEGE_FAULTS").as_deref() != Ok("disposable")
        || unsafe { nix::libc::geteuid() } != 0
        || unsafe { nix::libc::getuid() } != 0
        || !Path::new("/run/.containerenv").is_file()
        || fs::read_to_string("/proc/1/comm")?.trim() != "systemd"
    {
        bail!("root fault injection requires the explicit isolated systemd guest");
    }
    let input: Input = policy::parse(&custody::read_document(path, 0, 0o600)?)?;
    if input.schema != "dev-auth-privilege-native-input-v1" || !input.case.needs_fault_driver() {
        bail!("fault fixture case is not in the closed native matrix");
    }
    super::linux::fixture(&input.fixture_root)?;
    let approval_bytes = fs::read(&input.approval_plan)?;
    if policy::digest(&approval_bytes) != input.approval_sha256 {
        bail!("fault fixture approval changed");
    }
    let approval: policy::ApprovalPlan = policy::parse(&approval_bytes)?;
    let owner = approval.request.owner_uid;
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(&input.fixture_root)?;
    let metadata = root.metadata()?;
    if owner == 0 || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        bail!("fault fixture resource owner is invalid");
    }
    let mut core_proof = if matches!(
        input.case,
        Case::CoreCollector | Case::CoreCoordinatorDeath | Case::CoreBootstrapDeath
    ) {
        Some(super::privilege_native_core::Proof::prepare()?)
    } else {
        None
    };
    if input.case == Case::CoreCollector {
        return super::privilege_native_core::payload_driver(
            &input,
            &root,
            core_proof.take().context("core proof absent")?,
        );
    }
    if input.case == Case::NestedResourceMount {
        return nested::run(&input, &root, owner);
    }
    write_at(&root, "fault-driver-ready", input.case.name().as_bytes())?;
    if matches!(
        input.case,
        Case::HandoffBootstrapDeath | Case::ControllerGateBootstrapDeath
    ) {
        return handoff::run(&input, &root, owner);
    }
    let until = Instant::now() + Duration::from_secs(130);
    let session = loop {
        if let Ok(bytes) = read_at(&root, "session") {
            if let Ok(session) = String::from_utf8(bytes) {
                if protocol::token(&session).is_ok() {
                    break session;
                }
            }
        }
        ensure_before(until)?;
        pause();
    };
    let unit = PathBuf::from(format!(
        "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
    ));
    let observer_deadline = Instant::now() + Duration::from_secs(10);
    while read_at(&root, "observer-held").ok().as_deref() != Some(session.as_bytes()) {
        ensure_before(observer_deadline)?;
        pause();
    }
    let coordinator = exact_coordinator(&unit, &session)?;
    let coordinator_pidfd = pidfd(coordinator)?;
    if !pids(&unit)?.contains(&coordinator) {
        bail!("coordinator changed before pidfd retention");
    }
    let controller_path = unit.join("controller");
    let expected = [
        input.fixture_binary.as_os_str().as_encoded_bytes().to_vec(),
        b"controller".to_vec(),
        input.case.name().into_bytes(),
        input.dev_auth.as_os_str().as_encoded_bytes().to_vec(),
        input.fixture_root.as_os_str().as_encoded_bytes().to_vec(),
        input.approval_plan.as_os_str().as_encoded_bytes().to_vec(),
    ];
    let fixture_binary = fs::symlink_metadata(&input.fixture_binary)?;
    if !fixture_binary.is_file()
        || fixture_binary.uid() != 0
        || fixture_binary.mode() & 0o7777 != 0o755
    {
        bail!("fault fixture executable is not the root-owned ordinary subject");
    }
    let controller = pids(&controller_path)?
        .into_iter()
        .find(|pid| {
            fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == owner)
                && fs::metadata(format!("/proc/{pid}/exe")).is_ok_and(|m| {
                    (m.dev(), m.ino()) == (fixture_binary.dev(), fixture_binary.ino())
                })
                && fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|b| {
                    let mut parts = b.split(|v| *v == 0).collect::<Vec<_>>();
                    if parts.last() == Some(&b"".as_slice()) {
                        parts.pop();
                    }
                    parts == expected.iter().map(Vec::as_slice).collect::<Vec<_>>()
                })
        })
        .context("fault target lacks the exact pinned native controller")?;
    let _controller_pidfd = pidfd(controller)?;
    // Each fault is applied only after the detached root effect establishes
    // that both approved payload domains are populated.
    let active_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fs::metadata(input.fixture_root.join("scope/heartbeat"))
            .is_ok_and(|m| m.len() >= 10 && m.uid() == 0)
        {
            break;
        }
        ensure_before(active_deadline)?;
        pause();
    }
    if !populated(&unit)? {
        bail!("fault target domain is already empty");
    }
    require_setup_blocked()?;
    let mut replacement = None;
    let mut damaged = None;
    match input.case {
        Case::CoreCoordinatorDeath => {
            core_proof
                .as_mut()
                .context("core proof absent")?
                .retain(coordinator)?;
            signal(&coordinator_pidfd, nix::libc::SIGSEGV)?;
        }
        Case::CoordinatorDeath => signal(&coordinator_pidfd, nix::libc::SIGKILL)?,
        Case::BootstrapDeath | Case::CoreBootstrapDeath => {
            let parent = bootstrap_parent(coordinator)?;
            let parent_pidfd = pidfd(parent)?;
            let cmdline = fs::read(format!("/proc/{parent}/cmdline"))?;
            if !cmdline.split(|b| *b == 0).any(|v| v == b"admit-v1")
                || !cmdline
                    .split(|b| *b == 0)
                    .any(|v| v == input.approval_sha256.as_bytes())
            {
                bail!("bootstrap process does not match the pinned approval");
            }
            if input.case == Case::CoreBootstrapDeath {
                core_proof
                    .as_mut()
                    .context("core proof absent")?
                    .retain(parent)?;
                signal(&parent_pidfd, nix::libc::SIGSEGV)?;
            } else {
                signal(&parent_pidfd, nix::libc::SIGKILL)?;
            }
        }
        Case::GuardianDeath => {
            // The current native guardian is a transient systemd service, not
            // another daemon to kill. Terminate exactly its held unit domain.
            let mut kill = OpenOptions::new()
                .write(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(unit.join("cgroup.kill"))?;
            kill.write_all(b"1\n")?;
        }
        Case::PolicyReplaced => {
            replacement = Some(Replacement::apply(
                Path::new(custody::POLICY_PATH),
                &session,
            )?)
        }
        Case::HelperReplaced => {
            replacement = Some(Replacement::apply(
                Path::new(custody::HELPER_PATH),
                &session,
            )?)
        }
        Case::CleanupFailure => {
            let path = fs::read_dir(&unit)?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .is_some_and(|n| n.as_encoded_bytes().starts_with(b"operation-"))
                })
                .context("operation domain is absent")?;
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_dir() || metadata.uid() != 0 || !populated(&path)? {
                bail!("cleanup fault target is invalid");
            }
            // Invalidate retained custody rather than fabricate kernel evidence.
            // This must make cleanup unsuccessful even if systemd later kills
            // the payload and produces an independent emptiness observation.
            let held = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
                .open(&path)?;
            if (held.metadata()?.dev(), held.metadata()?.ino()) != (metadata.dev(), metadata.ino())
            {
                bail!("cleanup fault inode changed");
            }
            held.set_permissions(fs::Permissions::from_mode(0o777))?;
            damaged = Some((held, metadata.mode() & 0o7777));
        }
        Case::SetupExclusion => {}
        _ => bail!("unexpected root fault case"),
    }
    write_at(&root, "fault-applied", input.case.name().as_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(approval.request.hard_seconds + 25);
    let mut lock_gap = false;
    loop {
        let alive = unit.try_exists()? && populated(&unit)?;
        if !alive {
            break;
        }
        if setup_gap(&unit)? {
            lock_gap = true;
        }
        ensure_before(deadline)?;
        pause();
    }
    if let Some((held, mode)) = damaged {
        if held.metadata()?.nlink() != 0 {
            held.set_permissions(fs::Permissions::from_mode(mode))?;
        }
    }
    if let Some(replacement) = replacement {
        replacement.restore()?;
    }
    let released = Instant::now() + Duration::from_secs(8);
    while !setup_available()? {
        ensure_before(released)?;
        pause();
    }
    if lock_gap {
        bail!("setup exclusion was released while privileged domains were populated");
    }
    if let Some(proof) = core_proof {
        proof.finish()?;
    }
    write_at(&root, "fault-driver-passed", input.case.name().as_bytes())?;
    Ok(())
}
fn pause() {
    std::thread::sleep(Duration::from_millis(10));
}
fn ensure_before(until: Instant) -> Result<()> {
    if Instant::now() >= until {
        bail!("native fault fixture timed out");
    }
    Ok(())
}
pub(super) fn write_at(root: &File, name: &str, bytes: &[u8]) -> Result<()> {
    // Root markers live in the caller's held fixture directory, so use fd-bound
    // no-replace publication. Set exact readable mode on the retained inode;
    // inherited umask must not turn an observation document into root-only data.
    let temporary = format!(".{name}.pending-{}", std::process::id());
    let fd = rustix::fs::openat(
        root,
        temporary.as_str(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    file.sync_all()?;
    let held = file.metadata()?;
    let staged = rustix::fs::statat(
        root,
        temporary.as_str(),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    if (held.dev(), held.ino()) != (staged.st_dev, staged.st_ino) {
        bail!("fixture observation staging inode changed");
    }
    rustix::fs::renameat_with(
        root,
        temporary.as_str(),
        root,
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    let published = rustix::fs::statat(root, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if (held.dev(), held.ino()) != (published.st_dev, published.st_ino) {
        bail!("fixture observation publication inode changed");
    }
    root.sync_all()?;
    Ok(())
}

pub(super) fn read_at(root: &File, name: &str) -> Result<Vec<u8>> {
    let fd = rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() || file.metadata()?.len() > 4096 {
        bail!("invalid fixture synchronization file");
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn setup_available() -> Result<bool> {
    // Read-only feature seam enters the exact production writer exclusion,
    // including the orphan cgroup fence, then drops the lease without mutation.
    Ok(dev_auth::setup::native_fixture_probe_strong_writer_admission().is_ok())
}
fn setup_gap(unit: &Path) -> Result<bool> {
    if !payloads_populated(unit)? {
        return Ok(false);
    }
    let admitted = setup_available()?;
    Ok(admitted && payloads_populated(unit)?)
}
fn payloads_populated(unit: &Path) -> Result<bool> {
    let entries = match fs::read_dir(unit) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if name == "controller" || name.as_encoded_bytes().starts_with(b"operation-") {
            match populated(&entry.path()) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(_) if !entry.path().exists() => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(false)
}
fn require_setup_blocked() -> Result<()> {
    if setup_available()? {
        bail!("active native authority did not retain setup exclusion");
    }
    Ok(())
}
pub(super) fn populated(path: &Path) -> Result<bool> {
    Ok(fs::read_to_string(path.join("cgroup.events"))?
        .lines()
        .any(|line| line == "populated 1"))
}
pub(super) fn pids(path: &Path) -> Result<Vec<i32>> {
    fs::read_to_string(path.join("cgroup.procs"))?
        .lines()
        .map(|s| Ok(s.parse()?))
        .collect()
}
pub(super) fn exact_coordinator(unit: &Path, session: &str) -> Result<i32> {
    for pid in pids(unit)? {
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
        let parts = cmdline.split(|b| *b == 0).collect::<Vec<_>>();
        if fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == 0)
            && parts.contains(&b"serve-v1".as_slice())
            && parts.contains(&session.as_bytes())
        {
            return Ok(pid);
        }
    }
    bail!("native coordinator identity is absent")
}
fn bootstrap_parent(coordinator: i32) -> Result<i32> {
    // The coordinator is parented by PID 1. Locate the exact root bootstrap
    // through its accepted Unix-stream peer; /proc ownership and pinned argv
    // are checked before retaining a pidfd. The current protocol gives each
    // coordinator exactly one established handoff peer in its runtime directory.
    let session = fs::read(format!("/proc/{coordinator}/cmdline"))?;
    let fields = session.split(|b| *b == 0).collect::<Vec<_>>();
    let handoff = fields
        .windows(2)
        .find(|v| v[0] == b"--handoff")
        .context("handoff selector absent")?[1];
    let unix = fs::read_to_string("/proc/net/unix")?;
    let path = std::str::from_utf8(handoff)?;
    let inode = unix
        .lines()
        .find_map(|line| {
            let f = line.split_whitespace().collect::<Vec<_>>();
            (f.len() >= 8 && f[7] == path && f[3] == "00010000").then(|| f[6].to_owned())
        })
        .context("bootstrap listening inode absent")?;
    let target = format!("socket:[{inode}]");
    for entry in fs::read_dir("/proc")?.filter_map(Result::ok) {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if !fs::metadata(entry.path()).is_ok_and(|m| m.uid() == 0) {
            continue;
        }
        if let Ok(fds) = fs::read_dir(entry.path().join("fd")) {
            if fds.filter_map(Result::ok).any(|fd| {
                fs::read_link(fd.path())
                    .is_ok_and(|p| p.as_os_str() == std::ffi::OsStr::new(&target))
            }) {
                return Ok(pid);
            }
        }
    }
    bail!("exact bootstrap socket owner absent")
}
pub(super) fn pidfd(pid: i32) -> Result<OwnedFd> {
    let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
pub(super) fn signal(pidfd: &OwnedFd, signal: i32) -> Result<()> {
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<nix::libc::siginfo_t>(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
struct Replacement {
    path: PathBuf,
    retained: PathBuf,
    digest: String,
    original: File,
    replacement_identity: (u64, u64),
}
impl Replacement {
    fn apply(path: &Path, session: &str) -> Result<Self> {
        custody::validate_parents(path, 0, false)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
            bail!("replacement target has unsafe custody");
        }
        let original = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        if (original.metadata()?.dev(), original.metadata()?.ino())
            != (metadata.dev(), metadata.ino())
        {
            bail!("replacement original changed before retention");
        }
        let bytes = fs::read(path)?;
        let retained = path.with_file_name(format!("native-fixture-retained-{session}"));
        if retained.try_exists()? {
            bail!("replacement backup already exists");
        }
        fs::rename(path, &retained)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(metadata.mode() & 0o7777)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(Self {
            path: path.into(),
            retained,
            digest: policy::digest(&bytes),
            original,
            replacement_identity: (file.metadata()?.dev(), file.metadata()?.ino()),
        })
    }
    fn restore(self) -> Result<()> {
        let original = self.original.metadata()?;
        let retained = fs::symlink_metadata(&self.retained)?;
        let replacement = fs::symlink_metadata(&self.path)?;
        if (original.dev(), original.ino()) != (retained.dev(), retained.ino())
            || (replacement.dev(), replacement.ino()) != self.replacement_identity
        {
            bail!("fault restoration cannot adopt a replaced inode");
        }
        if policy::digest(&fs::read(&self.path)?) != self.digest {
            bail!("fault replacement changed before exact restoration");
        }
        fs::rename(self.retained, self.path)?;
        Ok(())
    }
}
