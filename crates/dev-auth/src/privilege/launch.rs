//! Explicit native approval and one-use custody handoffs for a reusable session.
use super::{
    custody, policy, protocol,
    runtime::{self, Admission, Controller},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    version: u32,
    approval: Vec<u8>,
    approval_sha256: String,
    controller: Controller,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    pub version: u32,
    pub session: String,
    pub owner_uid: u32,
    pub observation: protocol::Observation,
}

pub fn request(approval: Vec<u8>, digest: String, controller: Controller) -> Result<Terminal> {
    let uid = nix::unistd::getuid().as_raw();
    if uid == 0 || nix::unistd::geteuid().as_raw() != uid {
        bail!("administrative request requires a native non-root caller");
    }
    super::platform::require_caller_core_floor()?;
    crate::setup::validate_installed_maintenance_helper()?;
    let plan = policy::verify_plan(
        &approval,
        &digest,
        &custody::policy_bytes()?,
        &custody::installation_identity()?,
    )?;
    if plan.request.owner_uid != uid {
        bail!("administrative plan names a different native owner");
    }
    validate_controller(&controller)?;
    // Show exact bounded authority before the native authentication surface.
    eprintln!("Dev Auth administrator session: capability {}, owner {}, idle {} seconds, hard {} seconds, total uses {}",plan.request.capability,uid,plan.request.idle_seconds,plan.request.hard_seconds,plan.request.total_uses);
    for (name, op) in &plan.operations {
        eprintln!(
            "  operation {name}: at most {} uses; plans {}",
            op.max_uses,
            op.plans.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        for (id, p) in &op.plans {
            if op.protocol == super::receipt_install::PROTOCOL {
                let effect = super::receipt_install::validate_plan(op.adapter.as_ref(), p)?;
                eprintln!(
                    "    exact receipt effect: {}",
                    serde_json::to_string(&effect)?
                );
                eprintln!(
                    "    executor deployment: {}",
                    serde_json::to_string(&op.adapter)?
                );
            }
            eprintln!("    {id}: {} [{}]", p.executable, p.executable_sha256);
            eprintln!("      argv bytes: {}", serde_json::to_string(&p.arguments)?);
            eprintln!(
                "      cwd: {}; environment: {}",
                p.working_directory,
                serde_json::to_string(&p.environment)?
            );
            eprintln!(
                "      public input: {} bytes [{}]; timeout {}s; output limit {} bytes",
                p.input.len(),
                policy::digest(&p.input),
                p.timeout_seconds,
                p.output_limit
            );
            for (resource, r) in &p.resources {
                eprintln!("      {resource}: {:?} {}", r.access, r.path);
            }
        }
    }
    eprintln!("Approval digest: {digest}. Completed effects cannot be undone by revocation.");
    let base = PathBuf::from(format!("/run/user/{uid}"));
    let metadata = fs::symlink_metadata(&base)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        bail!("native user runtime directory is unsafe");
    }
    let private = tempfile::Builder::new().prefix("dap-").tempdir_in(base)?;
    let socket = private.path().join("approval.sock");
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut native_command = Command::new("/usr/bin/pkexec");
    native_command
        .arg("--disable-internal-agent")
        .arg(custody::HELPER_PATH)
        .arg("admit-v1")
        .arg("--socket")
        .arg(&socket)
        .arg("--owner")
        .arg(uid.to_string())
        .arg("--sha256")
        .arg(&digest)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Only native async-signal-safe set/getrlimit calls run in this child.
    unsafe {
        native_command.pre_exec(super::platform::constrain_core_limit);
    }
    let mut native = native_command
        .spawn()
        .context("start native administrator approval")?;
    let start = Instant::now();
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer = crate::linux_admission::peer_evidence(&stream)?;
                if peer.uid != 0 {
                    continue;
                }
                break stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if native.try_wait()?.is_some() {
            bail!("native administrator approval did not complete");
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = native.kill();
            let _ = native.wait();
            bail!("native administrator approval timed out before admission");
        }
        thread::sleep(Duration::from_millis(20));
    };
    protocol::write(
        &mut stream,
        &Proposal {
            version: 1,
            approval,
            approval_sha256: digest,
            controller,
        },
        protocol::CONTROL_BUDGET,
    )?;
    let bytes = protocol::read(
        &mut stream,
        Duration::from_secs(plan.request.hard_seconds + 30),
    )?;
    let terminal: Terminal = policy::parse(&bytes)?;
    protocol::token(&terminal.session)?;
    if terminal.version != 1 || terminal.owner_uid != uid {
        bail!("administrative native termination changed identity");
    }
    if !terminal.observation.cleanup_complete {
        // The independent custodian deliberately retains setup exclusion until
        // cleanup can be proven. Waiting for that process would suppress its
        // authenticated failure report indefinitely. Drop only our wait handle;
        // do not terminate the custodian or imply that teardown has completed.
        return Ok(terminal);
    }
    let status = native.wait()?;
    if status.success() != terminal.observation.terminal_success() {
        bail!("administrative native termination is inconsistent");
    }
    Ok(terminal)
}

pub fn admit(socket: &Path, owner_uid: u32, approved_digest: &str) -> Result<i32> {
    require_root()?;
    // An independent native custodian holds exclusion before handoff and until
    // whole-service cleanup, even if the coordinator is killed. Setup also
    // rejects populated orphan units, so custodian death cannot unlock work.
    let _exclusion = crate::setup_transition::admit(crate::setup::InstallMode::Strong)?;
    crate::setup::validate_running_maintenance_helper()?;
    let core_profile = super::platform::CoreDumpProfile::capture()?;
    policy::hex_digest(approved_digest)?;
    if owner_uid == 0 {
        bail!("administrative owner must be non-root");
    }
    custody::validate_parents(socket, owner_uid, false)?;
    let metadata = fs::symlink_metadata(socket)?;
    use std::os::unix::fs::FileTypeExt;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        bail!("administrative approval socket custody is invalid");
    }
    let mut client = UnixStream::connect(socket)?;
    let caller = crate::linux_admission::peer_evidence(&client)?;
    if caller.uid != owner_uid {
        bail!("native approval peer does not match its owner");
    }
    let proposal: Proposal =
        policy::parse(&protocol::read(&mut client, protocol::CONTROL_BUDGET)?)?;
    if proposal.version != 1 || proposal.approval_sha256 != approved_digest {
        bail!("native approval proposal changed identity");
    }
    validate_controller(&proposal.controller)?;
    let approval = policy::verify_plan(
        &proposal.approval,
        approved_digest,
        &custody::policy_bytes()?,
        &custody::installation_identity()?,
    )?;
    if approval.request.owner_uid != caller.uid {
        bail!("native approval changed its owner");
    }
    let login = super::login::LoginSession::bind(caller.pid, caller.uid)?;
    let approved_at = crate::linux_platform::boot_time_millis()?;
    let session = custody::random_id()?;
    prepare_runtime(&session)?;
    let directory = runtime::session_directory(&session)?;
    let handoff = directory.join("handoff.sock");
    let listener = UnixListener::bind(&handoff)?;
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let unit = format!("dev-auth-maintenance-{session}.service");
    let mut service = Command::new("/usr/bin/systemd-run")
        .args([
            "--quiet",
            "--wait",
            "--collect",
            "--pipe",
            "--service-type=exec",
            "--property=KillMode=control-group",
            "--property=SendSIGKILL=yes",
            "--property=TimeoutStopSec=5s",
            "--property=Delegate=no",
            "--property=Restart=no",
            "--property=UMask=0077",
            "--property=LimitCORE=1",
            "--property=OOMPolicy=stop",
        ])
        .arg(format!(
            "--property=RuntimeMaxSec={}s",
            approval.request.hard_seconds
        ))
        .arg(format!("--unit={unit}"))
        .arg("--uid=0")
        .arg("--gid=0")
        .arg("--")
        .arg(custody::HELPER_PATH)
        .arg("serve-v1")
        .arg("--session")
        .arg(&session)
        .arg("--handoff")
        .arg(&handoff)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let startup = Instant::now();
    let (mut connection, guardian_peer) = loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer = crate::linux_admission::peer_evidence(&stream)?;
                let expected = Path::new("/sys/fs/cgroup/system.slice").join(&unit);
                if peer.uid != 0 || peer.unified_cgroup != expected {
                    continue;
                }
                break (stream, peer);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if service.try_wait()?.is_some() {
            bail!("administrative guardian stopped before handoff");
        }
        if startup.elapsed() > Duration::from_secs(10) {
            stop_unit(&unit);
            let _ = service.wait();
            bail!("administrative guardian handoff timed out");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let guardian = GuardianObservation::open(&guardian_peer.unified_cgroup)?;
    protocol::write(
        &mut connection,
        &Admission {
            version: 1,
            session: session.clone(),
            approval: proposal.approval,
            approval_sha256: proposal.approval_sha256,
            approved_at_boot_ms: approved_at,
            login_session: login.path().to_owned(),
            controller: proposal.controller,
        },
        protocol::CONTROL_BUDGET,
    )?;
    let (tx, rx) = mpsc::channel();
    let budget = Duration::from_secs(approval.request.hard_seconds + 15);
    let reader = thread::spawn(move || {
        let result = protocol::read(&mut connection, budget)
            .and_then(|b| policy::parse::<protocol::Observation>(&b));
        let _ = tx.send(result);
    });
    let mut observed = None;
    loop {
        if observed.is_none() {
            if let Ok(result) = rx.try_recv() {
                observed = Some(result);
            }
        }
        if !peer_alive(&caller) || core_profile.verify().is_err() {
            stop_unit(&unit);
        }
        if let Some(status) = service.try_wait()? {
            if observed.is_none() {
                observed = Some(rx.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "administrative terminal observation unavailable"
                    ))
                }));
            }
            let _ = reader.join();
            let mut observation = observed
                .take()
                .and_then(Result::ok)
                .unwrap_or_else(|| unknown(approved_at, approval.request.hard_seconds));
            if !status.success() && observation.error_kind.is_none() {
                observation.outcome = "failed".into();
                observation.error_kind = Some("native_coordinator_failed".into());
            }
            // Independently prove all descendants gone before releasing the
            // bootstrap's setup exclusion. Preserve any earlier failure even
            // when systemd eventually obtains positive terminal cleanup.
            let until = Instant::now() + Duration::from_secs(6);
            let mut independently_clean = false;
            while Instant::now() < until {
                if !peer_alive(&guardian_peer) && guardian.empty_or_removed().unwrap_or(false) {
                    independently_clean = true;
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            observation.cleanup_complete &= independently_clean;
            if independently_clean {
                observation.cleanup_complete = true;
                let _ = fs::remove_file(directory.join("control.sock"));
            } else {
                observation.outcome = "failed".into();
                observation.error_kind = Some("whole_service_cleanup_unproven".into());
                // Keep the independent shared lease while positive cleanup is
                // unknown. If an administrator kills this custodian, setup's
                // kernel orphan-unit fence remains fail-closed.
                let failed = Terminal {
                    version: 1,
                    session: session.clone(),
                    owner_uid,
                    observation,
                };
                save_terminal(&directory, &failed)?;
                let _ = protocol::write(&mut client, &failed, protocol::CONTROL_BUDGET);
                loop {
                    if !peer_alive(&guardian_peer) && guardian.empty_or_removed().unwrap_or(false) {
                        let _ = fs::remove_file(directory.join("control.sock"));
                        let _ = fs::remove_file(&handoff);
                        return Ok(1);
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
            let terminal = Terminal {
                version: 1,
                session: session.clone(),
                owner_uid,
                observation,
            };
            save_terminal(&directory, &terminal)?;
            let code = if terminal.observation.terminal_success() {
                0
            } else {
                1
            };
            let _ = protocol::write(&mut client, &terminal, protocol::CONTROL_BUDGET);
            let _ = fs::remove_file(&handoff);
            return Ok(code);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn serve(session: &str, handoff: &Path) -> Result<i32> {
    require_root()?;
    crate::setup::validate_running_maintenance_helper()?;
    protocol::token(session)?;
    if handoff != runtime::session_directory(session)?.join("handoff.sock") {
        bail!("administrative handoff path is outside custody");
    }
    let endpoint = HandoffEndpoint::retain(handoff)?;
    let mut stream = UnixStream::connect(handoff)?;
    let peer = crate::linux_admission::peer_evidence(&stream)?;
    if peer.uid != 0 {
        bail!("administrative bootstrap is not native root");
    }
    // One-use listener naming ends after this authenticated connection. The
    // retained endpoint guard also unlinks on EOF/loss before admission, when
    // a killed bootstrap can no longer remove its own stale socket.
    drop(endpoint);
    let admission: Admission =
        policy::parse(&protocol::read(&mut stream, protocol::CONTROL_BUDGET)?)?;
    if admission.session != session {
        bail!("administrative handoff changed session identity");
    }
    let observation = runtime::serve(admission, &stream)?;
    protocol::write(&mut stream, &observation, protocol::CONTROL_BUDGET)?;
    Ok(if observation.terminal_success() { 0 } else { 1 })
}

struct HandoffEndpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl HandoffEndpoint {
    fn retain(path: &Path) -> Result<Self> {
        use std::os::unix::fs::FileTypeExt;
        custody::validate_parents(path, 0, false)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
        {
            bail!("administrative handoff endpoint custody is invalid");
        }
        Ok(Self {
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}
impl Drop for HandoffEndpoint {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == (self.device, self.inode))
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn terminal(session: &str, owner: u32) -> Result<Option<Terminal>> {
    let path = runtime::session_directory(session)?.join("result.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let terminal: Terminal = policy::parse(&custody::read_document(&path, 0, 0o644)?)?;
    if terminal.version != 1 || terminal.session != session || terminal.owner_uid != owner {
        bail!("administrative terminal observation changed identity");
    }
    Ok(Some(terminal))
}
fn save_terminal(directory: &Path, result: &Terminal) -> Result<()> {
    let bytes = policy::canonical(result)?;
    // The existing atomic document primitive sets exact mode on a private
    // retained temporary before no-clobber publication. Neither a restrictive
    // inherited umask nor a reader racing publication sees an invalid result.
    dev_tools_installation::write_atomic_document(
        &directory.join("result.json"),
        &bytes,
        &dev_tools_installation::DocumentAuthority {
            owner_uid: 0,
            mode: 0o644,
            limit: policy::DOCUMENT_LIMIT as u64,
        },
        None,
    )?;
    Ok(())
}

fn prepare_runtime(session: &str) -> Result<()> {
    let root = Path::new(custody::RUNTIME_PATH);
    if !root.try_exists()? {
        fs::create_dir(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o711))?;
    }
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o7777 != 0o711
    {
        bail!("administrative runtime root custody is invalid");
    }
    let path = runtime::session_directory(session)?;
    fs::create_dir(&path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o711))?;
    Ok(())
}
fn validate_controller(c: &Controller) -> Result<()> {
    if c.executable.is_empty()
        || c.executable.len() > 4096
        || c.executable.contains(&0)
        || !PathBuf::from(std::ffi::OsString::from_vec(c.executable.clone())).is_absolute()
        || c.cwd.is_empty()
        || c.cwd.len() > 4096
        || c.cwd.contains(&0)
        || !PathBuf::from(std::ffi::OsString::from_vec(c.cwd.clone())).is_absolute()
        || c.arguments.len() > 256
        || c.arguments.iter().any(|a| a.contains(&0))
        || c.arguments.iter().map(Vec::len).sum::<usize>() > 64 * 1024
        || c.environment.len() > 64
    {
        bail!("native controller request exceeds bounds");
    }
    for (k, v) in &c.environment {
        if k.is_empty()
            || k.contains(['=', '\0'])
            || v.contains('\0')
            || k.len() > 128
            || v.len() > 4096
            || !allowed_environment(k)
        {
            bail!("native controller environment is outside public inheritance");
        }
    }
    Ok(())
}
pub fn allowed_environment(k: &str) -> bool {
    matches!(
        k,
        "PATH"
            | "TERM"
            | "COLORTERM"
            | "LANG"
            | "TZ"
            | "DISPLAY"
            | "WAYLAND_DISPLAY"
            | "DBUS_SESSION_BUS_ADDRESS"
    ) || k.starts_with("LC_")
}
fn require_root() -> Result<()> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        bail!("administrative infrastructure requires native root");
    }
    Ok(())
}
fn peer_alive(peer: &crate::linux_admission::LinuxPeerEvidence) -> bool {
    let mut poll = nix::libc::pollfd {
        fd: peer.peer_pidfd().as_fd().as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    unsafe { nix::libc::poll(&mut poll, 1, 0) == 0 }
}
fn stop_unit(unit: &str) {
    let _ = Command::new("/usr/bin/systemctl")
        .args(["kill", "--kill-whom=all", "--signal=KILL", unit])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
fn unknown(approved: u64, duration: u64) -> protocol::Observation {
    protocol::Observation {
        version: 1,
        outcome: "failed".into(),
        started: None,
        exit_code: Some(1),
        signal: None,
        remaining_uses: 0,
        hard_deadline_boot_ms: approved.saturating_add(duration.saturating_mul(1000)),
        cleanup_complete: false,
        error_kind: Some("native_terminal_cleanup_unproven".into()),
    }
}

// The bootstrap created this exact service and authenticated its root main peer
// before opening the domain. This is observation only, not arbitrary adoption or
// a grant. Kernel cgroup removal requires an empty domain.
struct GuardianObservation {
    path: PathBuf,
    directory: File,
    parent: File,
    device: u64,
    inode: u64,
    parent_device: u64,
    parent_inode: u64,
}
impl GuardianObservation {
    fn open(path: &Path) -> Result<Self> {
        custody::validate_parents(&path.join("leaf"), 0, false)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        if rustix::fs::fstatfs(&directory)?.f_type as u64 != 0x6367_7270 {
            bail!("guardian observation requires kernel cgroup evidence");
        }
        let m = directory.metadata()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!("guardian observation custody is invalid");
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path.parent().context("guardian parent is absent")?)?;
        let pm = parent.metadata()?;
        Ok(Self {
            path: path.into(),
            directory,
            parent,
            device: m.dev(),
            inode: m.ino(),
            parent_device: pm.dev(),
            parent_inode: pm.ino(),
        })
    }
    fn empty_or_removed(&self) -> Result<bool> {
        let parent_named =
            fs::symlink_metadata(self.path.parent().context("guardian parent is absent")?)?;
        let parent_held = self.parent.metadata()?;
        if (parent_named.dev(), parent_named.ino()) != (self.parent_device, self.parent_inode)
            || (parent_held.dev(), parent_held.ino()) != (self.parent_device, self.parent_inode)
        {
            bail!("guardian parent identity changed");
        }
        let named = match fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e.into()),
        };
        if (named.dev(), named.ino()) != (self.device, self.inode) {
            bail!("guardian domain identity changed");
        }
        let fd = rustix::fs::openat(
            &self.directory,
            "cgroup.events",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let mut text = String::new();
        use std::io::Read;
        File::from(fd).take(4097).read_to_string(&mut text)?;
        if text.len() > 4096 {
            bail!("guardian population evidence exceeds bounds");
        }
        let population = text
            .lines()
            .filter_map(|line| line.strip_prefix("populated "))
            .collect::<Vec<_>>();
        match population.as_slice() {
            ["0"] => Ok(true),
            ["1"] => Ok(false),
            _ => bail!("guardian population evidence is ambiguous"),
        }
    }
}
