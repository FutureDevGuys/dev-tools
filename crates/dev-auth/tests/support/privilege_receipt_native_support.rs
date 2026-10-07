//! Real standalone installer acceptance; no synthetic privileged payload.
#[path = "privilege_receipt_native_contract.rs"]
pub mod contract;
use super::privilege_native_faults as fault;
use anyhow::{bail, Context, Result};
use contract::{Case, Input};
use dev_auth::privilege::{custody, policy, protocol, receipt_install as effect};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::ExitStatusExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn guest(require_opt_in: bool) -> Result<()> {
    if (require_opt_in
        && std::env::var("DEV_AUTH_NATIVE_RECEIPT_FIXTURE").as_deref() != Ok("disposable"))
        || !Path::new("/run/.containerenv").is_file()
        || fs::read_to_string("/proc/1/comm")?.trim() != "systemd"
    {
        bail!("real receipt acceptance requires the explicit disposable systemd guest");
    }
    dev_auth::privilege::platform::CoreDumpProfile::capture()?.verify()
}
fn private_root(input: &Input, owner: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&input.fixture_root)?;
    let m = file.metadata()?;
    if m.uid() != owner || m.mode() & 0o7777 != 0o700 {
        bail!("receipt fixture root ownership changed");
    }
    Ok(file)
}
fn until(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        bail!("real receipt fixture timed out");
    }
    Ok(())
}
fn pause() {
    std::thread::sleep(Duration::from_millis(2));
}
fn public_marker(root: &File, name: &str, expected: &[u8]) -> Result<bool> {
    let fd = match rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(v) => v,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let file = File::from(fd);
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o7777 != 0o644 || m.nlink() != 1 {
        bail!("root receipt fixture marker is untrusted");
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    Ok(bytes == expected)
}
fn wait_marker(root: &File, name: &str, expected: &[u8], deadline: Instant) -> Result<()> {
    while !public_marker(root, name, expected)? {
        until(deadline)?;
        pause();
    }
    Ok(())
}
fn user_marker(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    custody::write_new_document(&root.join(name), bytes, nix::unistd::getuid().as_raw())
}

pub fn controller(path: &Path) -> Result<()> {
    // The grant intentionally strips fixture environment variables; this
    // non-root controller is pinned by its explicit argv/input instead.
    guest(false)?;
    let uid = nix::unistd::getuid().as_raw();
    if uid == 0 || nix::unistd::geteuid().as_raw() != uid {
        bail!("receipt controller must remain the native non-root owner");
    }
    let (input, approval) = contract::read(path, uid)?;
    if approval.request.owner_uid != uid {
        bail!("receipt controller owner differs");
    }
    let root = private_root(&input, uid)?;
    let session = std::env::var("DEV_AUTH_PRIVILEGE_SESSION")?;
    protocol::token(&session)?;
    if input.case == Case::AliasDenied {
        user_marker(
            &input.fixture_root,
            "unexpected-controller-release",
            session.as_bytes(),
        )?;
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    user_marker(&input.fixture_root, "session", session.as_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(approval.request.hard_seconds + 15);
    wait_marker(&root, "real-driver-bound", session.as_bytes(), deadline)?;
    let mut count = 0;
    let mut invoke = |id: &str, expected: Expected| -> Result<()> {
        count += 1;
        let result = input.fixture_root.join(format!("result-{count}.json"));
        let output = Command::new(&input.dev_auth)
            .args([
                "privilege",
                "execute-plan",
                "--session",
                &session,
                "--operation",
                "receipt",
                "--plan-id",
                id,
                "--result-file",
            ])
            .arg(&result)
            .stdin(Stdio::null())
            .output()?;
        let observation: protocol::Observation =
            policy::parse(&custody::read_document(&result, uid, 0o600)?)?;
        if !observation.cleanup_complete || observation.started != Some(true) {
            bail!("real installer operation lacks native cleanup proof");
        }
        match expected {
            Expected::Success(outcome) => {
                if !output.status.success()
                    || observation.exit_code != Some(0)
                    || observation.signal.is_some()
                    || observation.error_kind.is_some()
                {
                    bail!("real installer operation failed");
                }
                let request = contract::plan(&approval, id)?;
                let report = effect::verify_report(&request, &output.stdout, 0)?;
                if !outcome.contains(&report.outcome.as_str()) {
                    bail!("real installer outcome differs");
                }
            }
            Expected::Missing => {
                if output.status.success() {
                    bail!("fresh system target unexpectedly existed");
                }
            }
            Expected::Killed => {
                if output.status.signal() != Some(nix::libc::SIGKILL)
                    || observation.signal != Some(nix::libc::SIGKILL)
                    || observation.exit_code.is_some()
                {
                    bail!("journal interruption did not preserve native signal");
                }
            }
        }
        Ok(())
    };
    invoke("status-a", Expected::Missing)?;
    if input.case != Case::Transaction {
        user_marker(&input.fixture_root, "interrupt-ready", b"install-a")?;
        // Driver freezes the real installer only after its approved journal is
        // pending. Independent revoke/expiry must kill the stopped operation.
        let _ = invoke("install-a", Expected::Killed);
        loop {
            until(deadline)?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    invoke("install-a", Expected::Success(&["changed"]))?;
    invoke("status-a", Expected::Success(&["current"]))?;
    invoke("install-a", Expected::Success(&["unchanged"]))?;
    user_marker(&input.fixture_root, "interrupt-ready", b"install-b")?;
    invoke("install-b", Expected::Killed)?;
    wait_marker(&root, "real-interrupted", b"install-b", deadline)?;
    invoke("resume-b", Expected::Success(&["changed", "unchanged"]))?;
    invoke("status-b", Expected::Success(&["current"]))?;
    invoke("rollback-a", Expected::Success(&["changed"]))?;
    invoke("status-a", Expected::Success(&["current"]))?;
    user_marker(
        &input.fixture_root,
        "real-work-complete",
        session.as_bytes(),
    )?;
    // Observer explicitly revokes this same reused grant; it never approves
    // another one for the separate transactions.
    loop {
        until(deadline)?;
        std::thread::sleep(Duration::from_millis(20));
    }
}
enum Expected<'a> {
    Success(&'a [&'a str]),
    Missing,
    Killed,
}

pub fn driver(path: &Path) -> Result<()> {
    guest(true)?;
    if nix::unistd::getuid().as_raw() != 0 || nix::unistd::geteuid().as_raw() != 0 {
        bail!("real receipt driver requires explicit native root authorization");
    }
    let (input, approval) = contract::read(path, 0)?;
    dev_auth::setup::native_fixture_probe_strong_writer_admission()?;
    let owner = approval.request.owner_uid;
    let root = private_root(&input, owner)?;
    let controller = custody::held_root_executable(&input.controller, &input.controller_sha256)?;
    let controller_image = controller.open_read_handle()?.metadata()?;
    let operation = &approval.operations["receipt"];
    let binding = operation
        .adapter
        .as_ref()
        .context("real executor receipt absent")?;
    let first = &operation.plans["install-a"];
    let proof = custody::read_document(Path::new(&binding.receipt_path), 0, 0o644)?;
    if policy::digest(&proof) != binding.receipt_sha256 {
        bail!("independent executor receipt changed");
    }
    let a = contract::plan(&approval, "install-a")?;
    let b = contract::plan(&approval, "install-b")?;
    for (artifact, receipt) in [
        (&a.candidate, &input.receipt_a),
        (&b.candidate, &input.receipt_b),
    ] {
        verify_generation(&a, artifact, receipt)?;
    }
    if input.case == Case::AliasDenied {
        let destination = fs::metadata(&a.destination)?;
        let protected = fs::metadata(
            Path::new(&first.executable)
                .parent()
                .context("executor parent absent")?,
        )?;
        if (destination.dev(), destination.ino()) != (protected.dev(), protected.ino()) {
            bail!("alias-negative fixture requires an explicitly provisioned protected-parent bind alias");
        }
        fault::write_at(&root, "real-driver-ready", input.approval_sha256.as_bytes())?;
        let deadline = Instant::now() + Duration::from_secs(200);
        while fault::read_at(&root, "alias-terminal").ok().as_deref()
            != Some(input.approval_sha256.as_bytes())
        {
            until(deadline)?;
            pause();
        }
        if dev_auth::setup::native_fixture_probe_strong_writer_admission().is_err() {
            bail!("alias denial left populated root authority");
        }
        fault::write_at(
            &root,
            "real-driver-complete",
            input.approval_sha256.as_bytes(),
        )?;
        return Ok(());
    }
    if Path::new(&a.destination).join(&a.binary).exists()
        || Path::new(&a.destination)
            .join(format!(".{}.syscfg-rust.json", a.binary))
            .exists()
        || Path::new(&a.journal).join("state.json").exists()
    {
        bail!("real receipt target/journal must be fresh");
    }
    // An operator-created unrelated sentinel must survive byte-for-byte.
    let sentinel = Path::new(&a.destination).join("unrelated-sentinel");
    let sentinel_bytes = custody::read_document(&sentinel, 0, 0o644)?;
    fault::write_at(&root, "real-driver-ready", input.approval_sha256.as_bytes())?;
    let startup = Instant::now() + Duration::from_secs(150);
    let session = loop {
        if let Ok(bytes) = fault::read_at(&root, "session") {
            if let Ok(value) = String::from_utf8(bytes) {
                if protocol::token(&value).is_ok() {
                    break value;
                }
            }
        }
        until(startup)?;
        pause();
    };
    let unit = PathBuf::from(format!(
        "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
    ));
    let held = HeldDomain::open(unit.clone())?;
    let coordinator = fault::exact_coordinator(&unit, &session)?;
    let coordinator_fd = fault::pidfd(coordinator)?;
    let expected = [
        input.controller.as_os_str().as_encoded_bytes().to_vec(),
        b"receipt-controller".to_vec(),
        input
            .approval_plan
            .parent()
            .context("approval parent absent")?
            .join("real-input.json")
            .as_os_str()
            .as_encoded_bytes()
            .to_vec(),
    ];
    let mut found = false;
    for pid in fault::pids(&unit.join("controller"))? {
        let bytes = fs::read(format!("/proc/{pid}/cmdline"))?;
        let args = bytes
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let image = fs::metadata(format!("/proc/{pid}/exe"))?;
        if args == expected
            && fs::metadata(format!("/proc/{pid}"))?.uid() == owner
            && (image.dev(), image.ino()) == (controller_image.dev(), controller_image.ino())
        {
            found = true;
        }
    }
    if !found {
        bail!("real receipt controller does not match pinned native invocation");
    }
    if dev_auth::setup::native_fixture_probe_strong_writer_admission().is_ok() {
        bail!("setup admitted while the real grant was active");
    }
    fault::write_at(&root, "real-driver-bound", session.as_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(approval.request.hard_seconds + 20);
    let action = if input.case == Case::Transaction {
        "install-b"
    } else {
        "install-a"
    };
    loop {
        if fault::read_at(&root, "interrupt-ready").ok().as_deref() == Some(action.as_bytes()) {
            break;
        }
        until(deadline)?;
        pause();
    }
    let expected_receipt: serde_json::Value = serde_json::from_slice(if action == "install-b" {
        &input.receipt_b
    } else {
        &input.receipt_a
    })?;
    let journal = Path::new(&a.journal).join("state.json");
    let image = fs::symlink_metadata(&first.executable)?;
    let mut killed = false;
    while !killed {
        until(deadline)?;
        if let Ok(bytes) = custody::read_document(&journal, 0, 0o600) {
            let record: serde_json::Value = serde_json::from_slice(&bytes)?;
            if record["phase"] == "pending" && record["expected"] == expected_receipt {
                for domain in fs::read_dir(&unit)? {
                    let domain = domain?;
                    if !domain
                        .file_name()
                        .as_encoded_bytes()
                        .starts_with(b"operation-")
                    {
                        continue;
                    }
                    for pid in fault::pids(&domain.path())? {
                        let Ok(executable) = fs::metadata(format!("/proc/{pid}/exe")) else {
                            continue;
                        };
                        if (executable.dev(), executable.ino()) != (image.dev(), image.ino()) {
                            continue;
                        }
                        let fd = fault::pidfd(pid)?;
                        let args = fs::read(format!("/proc/{pid}/cmdline"))?;
                        let expected_args =
                            format!("{}\0maintenance-v1\0", first.executable).into_bytes();
                        if args != expected_args || !fault::pids(&domain.path())?.contains(&pid) {
                            bail!("real installer changed before fault");
                        }
                        // Freeze before the final journal check. A missed Pending
                        // window is failure, never reclassified as interruption.
                        let stopped = Stopped::new(fd, pid)?;
                        let current: serde_json::Value =
                            serde_json::from_slice(&custody::read_document(&journal, 0, 0o600)?)?;
                        if current["phase"] != "pending" || current["expected"] != expected_receipt
                        {
                            bail!("real installer interruption window was missed");
                        }
                        if input.case == Case::Transaction {
                            fault::signal(&stopped.fd, nix::libc::SIGKILL)?;
                            fault::write_at(&root, "real-interrupted", action.as_bytes())?;
                        } else {
                            fault::write_at(&root, "real-stopped", action.as_bytes())?;
                        }
                        if input.case != Case::Transaction {
                            while !held.empty_or_removed()? {
                                until(deadline)?;
                                pause();
                            }
                        }
                        drop(stopped);
                        killed = true;
                        break;
                    }
                    if killed {
                        break;
                    }
                }
            }
        }
        if !killed {
            pause();
        }
    }
    while !held.empty_or_removed()? {
        until(deadline)?;
        pause();
    }
    if alive(&coordinator_fd)? {
        bail!("coordinator outlived positive real-transaction cleanup");
    }
    if custody::read_document(&sentinel, 0, 0o644)? != sentinel_bytes {
        bail!("real installer changed unrelated sentinel");
    }
    if input.case == Case::Transaction {
        verify_installed(&a, &input.receipt_a)?;
    }
    if dev_auth::setup::native_fixture_probe_strong_writer_admission().is_err() {
        bail!("setup exclusion remained after positive cleanup");
    }
    fault::write_at(&root, "real-driver-complete", session.as_bytes())?;
    Ok(())
}
fn verify_generation(
    request: &effect::Request,
    artifact: &effect::Artifact,
    receipt: &[u8],
) -> Result<()> {
    let root = Path::new(&artifact.generation);
    custody::validate_parents(&root.join("receipt.json"), 0, false)?;
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        bail!("real generation custody differs");
    }
    if custody::read_document(&root.join("receipt.json"), 0, 0o600)? != receipt {
        bail!("real generation receipt differs from independent bytes");
    }
    let record: serde_json::Value = serde_json::from_slice(receipt)?;
    let expected = record["artifact_sha256"]
        .as_str()
        .context("artifact hash absent")?
        .strip_prefix("sha256:")
        .context("artifact hash invalid")?;
    let image = root.join(&request.binary);
    let metadata = fs::symlink_metadata(&image)?;
    if metadata.uid() != 0
        || metadata.nlink() != 1
        || !metadata.is_file()
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o100 == 0
        || metadata.len()
            != record["artifact_bytes"]
                .as_u64()
                .context("artifact size absent")?
        || policy::digest(&fs::read(image)?) != expected
    {
        bail!("real generation artifact differs");
    }
    Ok(())
}
fn verify_installed(request: &effect::Request, receipt: &[u8]) -> Result<()> {
    let directory = Path::new(&request.destination);
    let record: serde_json::Value = serde_json::from_slice(receipt)?;
    let image = directory.join(&request.binary);
    let m = fs::symlink_metadata(&image)?;
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7022 != 0
        || m.mode() & 0o100 == 0
        || format!("sha256:{}", policy::digest(&fs::read(&image)?))
            != record["artifact_sha256"]
                .as_str()
                .context("artifact hash absent")?
    {
        bail!("final real artifact differs");
    }
    if custody::read_document(
        &directory.join(format!(".{}.syscfg-rust.json", request.binary)),
        0,
        0o600,
    )? != receipt
    {
        bail!("final real receipt differs");
    }
    Ok(())
}
fn alive(fd: &OwnedFd) -> Result<bool> {
    let mut p = nix::libc::pollfd {
        fd: fd.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let r = unsafe { nix::libc::poll(&mut p, 1, 0) };
    if r < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(r == 0)
}
struct Stopped {
    fd: OwnedFd,
}
impl Stopped {
    fn new(fd: OwnedFd, pid: i32) -> Result<Self> {
        fault::signal(&fd, nix::libc::SIGSTOP)?;
        let stopped = Self { fd };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            if status
                .lines()
                .any(|line| line.starts_with("State:\tT") || line.starts_with("State:\tt"))
            {
                break;
            }
            until(deadline)?;
            pause();
        }
        Ok(stopped)
    }
}
impl Drop for Stopped {
    fn drop(&mut self) {
        let _ = fault::signal(&self.fd, nix::libc::SIGCONT);
    }
}

/// Independent kernel evidence; a product success report alone is insufficient.
pub struct HeldDomain {
    path: PathBuf,
    file: File,
    identity: (u64, u64),
    parent: File,
    parent_identity: (u64, u64),
}
impl HeldDomain {
    pub fn open(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&path)?;
        let m = file.metadata()?;
        if m.uid() != 0 || rustix::fs::fstatfs(&file)?.f_type as u64 != 0x6367_7270 {
            bail!("real receipt domain is not kernel root authority");
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(path.parent().context("domain parent absent")?)?;
        let pm = parent.metadata()?;
        Ok(Self {
            path,
            file,
            identity: (m.dev(), m.ino()),
            parent,
            parent_identity: (pm.dev(), pm.ino()),
        })
    }
    pub fn empty_or_removed(&self) -> Result<bool> {
        let p = self.parent.metadata()?;
        let named = fs::symlink_metadata(self.path.parent().context("domain parent absent")?)?;
        if (p.dev(), p.ino()) != self.parent_identity
            || (named.dev(), named.ino()) != self.parent_identity
        {
            bail!("real receipt domain parent changed");
        }
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.into()),
            Ok(m) => {
                if (m.dev(), m.ino()) != self.identity {
                    bail!("real receipt domain was replaced");
                }
                let fd = rustix::fs::openat(
                    &self.file,
                    "cgroup.events",
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )?;
                let mut bytes = String::new();
                File::from(fd).take(4097).read_to_string(&mut bytes)?;
                if bytes.len() > 4096 {
                    bail!("domain evidence exceeded bounds");
                }
                match bytes
                    .lines()
                    .filter_map(|s| s.strip_prefix("populated "))
                    .collect::<Vec<_>>()
                    .as_slice()
                {
                    ["0"] => Ok(true),
                    ["1"] => Ok(false),
                    _ => bail!("domain population ambiguous"),
                }
            }
        }
    }
}
