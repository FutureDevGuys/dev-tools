//! Early native handoff fault. A missed pre-controller window is a failed run.
use super::*;
use std::collections::BTreeSet;

struct Stopped {
    pidfd: OwnedFd,
    pid: i32,
}
impl Stopped {
    fn retain_and_stop(pid: i32) -> Result<Self> {
        let value = Self {
            pidfd: pidfd(pid)?,
            pid,
        };
        signal(&value.pidfd, nix::libc::SIGSTOP)?;
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            if status
                .lines()
                .any(|line| line.starts_with("State:\tT") || line.starts_with("State:\tt"))
            {
                return Ok(value);
            }
            ensure_before(until)?;
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Stopped {
    fn drop(&mut self) {
        let _ = signal(&self.pidfd, nix::libc::SIGCONT);
    }
}
fn alive(fd: &OwnedFd) -> Result<bool> {
    let mut poll = nix::libc::pollfd {
        fd: fd.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let value = unsafe { nix::libc::poll(&mut poll, 1, 0) };
    if value < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value == 0)
}
fn children(pid: i32) -> Result<Vec<i32>> {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))?
        .split_whitespace()
        .map(|s| Ok(s.parse()?))
        .collect()
}
fn cmdline(pid: i32) -> Result<Vec<Vec<u8>>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(bytes
        .split(|v| *v == 0)
        .filter(|v| !v.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}
fn listener_session(pid: i32, require_named: bool) -> Result<Option<String>> {
    let sockets = fs::read_dir(format!("/proc/{pid}/fd"))?
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter_map(|p| p.to_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for line in fs::read_to_string("/proc/net/unix")?.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 8
            || fields[3] != "00010000"
            || !sockets.contains(&format!("socket:[{}]", fields[6]))
        {
            continue;
        }
        let path = Path::new(fields[7]);
        if path.file_name() != Some(std::ffi::OsStr::new("handoff.sock")) {
            continue;
        }
        let Some(session) = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
        else {
            continue;
        };
        if protocol::token(session).is_ok()
            && path
                == dev_auth::privilege::runtime::session_directory(session)?.join("handoff.sock")
        {
            if require_named {
                let meta = fs::symlink_metadata(path)?;
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() || meta.uid() != 0 || meta.mode() & 0o7777 != 0o600
                {
                    bail!("handoff listener custody is invalid");
                }
            }
            return Ok(Some(session.into()));
        }
    }
    Ok(None)
}
pub(super) fn run(input: &Input, root: &File, owner: u32) -> Result<()> {
    let require_gate = input.case == Case::ControllerGateBootstrapDeath;
    let until = Instant::now() + Duration::from_secs(130);
    let frontend = loop {
        if let Ok(bytes) = read_at(root, "frontend-pid") {
            if let Ok(text) = String::from_utf8(bytes) {
                if let Ok(pid) = text.parse::<i32>() {
                    break pid;
                }
            }
        }
        ensure_before(until)?;
        std::thread::sleep(Duration::from_millis(1));
    };
    let frontend_pidfd = pidfd(frontend)?;
    let front_args = cmdline(frontend)?;
    let executable = fs::metadata(&input.dev_auth)?;
    let running = fs::metadata(format!("/proc/{frontend}/exe"))?;
    if fs::metadata(format!("/proc/{frontend}"))?.uid() != owner
        || (executable.dev(), executable.ino()) != (running.dev(), running.ino())
        || !front_args
            .iter()
            .any(|v| v == input.approval_sha256.as_bytes())
        || !front_args
            .iter()
            .any(|v| v == input.fixture_root.as_os_str().as_encoded_bytes())
        || !front_args.iter().any(|v| v == input.case.name().as_bytes())
    {
        bail!("early handoff frontend is outside the pinned fixture");
    }
    let (bootstrap, session, unit) = 'discover: loop {
        if !alive(&frontend_pidfd)? {
            bail!("frontend exited before bootstrap handoff");
        }
        for pid in children(frontend)? {
            if !fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == 0) {
                continue;
            }
            let Ok(args) = cmdline(pid) else {
                continue;
            };
            if !args.iter().any(|v| v == b"admit-v1")
                || !args.iter().any(|v| v == input.approval_sha256.as_bytes())
            {
                continue;
            }
            if let Some(session) = listener_session(pid, !require_gate)? {
                let unit = PathBuf::from(format!(
                    "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
                ));
                if unit.try_exists()? && (!require_gate || unit.join("controller").try_exists()?) {
                    break 'discover (pid, session, unit);
                }
            }
        }
        ensure_before(until)?;
        std::thread::sleep(Duration::from_millis(1));
    };
    let bootstrap = Stopped::retain_and_stop(bootstrap)?;
    if listener_session(bootstrap.pid, !require_gate)?.as_deref() != Some(session.as_str()) {
        bail!("bootstrap changed its exact handoff listener");
    }
    let main_deadline = Instant::now() + Duration::from_secs(2);
    let main = loop {
        if let Ok(pid) = exact_coordinator(&unit, &session) {
            break Stopped::retain_and_stop(pid)?;
        }
        ensure_before(main_deadline)?;
        std::thread::sleep(Duration::from_millis(1));
    };
    let gated = if require_gate {
        let pid = gated_child(&unit, main.pid)?;
        Some((pid, pidfd(pid)?))
    } else {
        None
    };
    let service_children = children(bootstrap.pid)?;
    let mut service_pidfds = Vec::new();
    for child in service_children {
        let fd = pidfd(child)?;
        let args = cmdline(child)?;
        if !args
            .iter()
            .any(|v| v == format!("--unit=dev-auth-maintenance-{session}.service").as_bytes())
        {
            bail!("bootstrap has an unexpected descendant before handoff");
        }
        service_pidfds.push(fd);
    }
    if service_pidfds.is_empty() {
        bail!("retained systemd-run owner is absent");
    }
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(&unit)?;
    if rustix::fs::fstatfs(&held)?.f_type as u64 != 0x6367_7270 {
        bail!("handoff domain is not native cgroup-v2");
    }
    let identity = (held.metadata()?.dev(), held.metadata()?.ino());
    let pre_controller = || -> Result<()> {
        if read_at(root, "session").is_ok() {
            bail!("controller already ran before handoff fault");
        }
        if let Some((pid, fd)) = &gated {
            if !alive(fd)? || gated_child(&unit, main.pid)? != *pid {
                bail!("retained controller gate precondition was lost");
            }
        } else if unit.join("controller").try_exists()? {
            bail!("pre-controller handoff window was missed; run is not active-session coverage");
        }
        Ok(())
    };
    pre_controller()?;
    write_at(root, "handoff-prepared", session.as_bytes())?;
    let handshake = Instant::now() + Duration::from_secs(5);
    while read_at(root, "observer-held").ok().as_deref() != Some(session.as_bytes()) {
        ensure_before(handshake)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    pre_controller()?;
    signal(&bootstrap.pidfd, nix::libc::SIGKILL)?;
    signal(&main.pidfd, nix::libc::SIGCONT)?;
    write_at(root, "fault-applied", input.case.name().as_bytes())?;
    let terminal = Instant::now() + Duration::from_secs(80);
    loop {
        // Probe immediately after the fault and while the retained main still
        // exists. No writer mutation occurs, including in the orphan case.
        let writer_admitted = setup_available()?;
        let main_alive = alive(&main.pidfd)?;
        if writer_admitted && main_alive {
            bail!("early handoff loss admitted setup before guardian termination");
        }
        let services_alive = service_pidfds
            .iter()
            .map(alive)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .any(|v| v);
        let child_alive = gated
            .as_ref()
            .map(|(_, fd)| alive(fd))
            .transpose()?
            .unwrap_or(false);
        if !main_alive && !services_alive && !child_alive && !unit.try_exists()? {
            break;
        }
        if let Ok(named) = fs::symlink_metadata(&unit) {
            if (named.dev(), named.ino()) != identity {
                bail!("early handoff cgroup identity changed");
            }
        }
        ensure_before(terminal)?;
        pause();
    }
    if read_at(root, "session").is_ok() {
        bail!("controller released after early bootstrap death");
    }
    for leaf in ["control.sock", "handoff.sock"] {
        if dev_auth::privilege::runtime::session_directory(&session)?
            .join(leaf)
            .try_exists()?
        {
            bail!("early handoff left a stale native endpoint");
        }
    }
    if !setup_available()? {
        bail!("early handoff cleanup did not release setup exclusion");
    }
    write_at(root, "fault-driver-passed", input.case.name().as_bytes())?;
    Ok(())
}

fn gated_child(unit: &Path, coordinator: i32) -> Result<i32> {
    let children = pids(&unit.join("controller"))?;
    if children.len() != 1 {
        bail!("controller gate must retain exactly one native pre-exec child");
    }
    let child = children[0];
    let status = fs::read_to_string(format!("/proc/{child}/status"))?;
    let current = fs::metadata(format!("/proc/{child}/exe"))?;
    let expected = fs::metadata(format!("/proc/{coordinator}/exe"))?;
    let syscall = fs::read_to_string(format!("/proc/{child}/syscall"))?;
    let fields = syscall.split_whitespace().collect::<Vec<_>>();
    if fs::metadata(format!("/proc/{child}"))?.uid() != 0
        || (current.dev(), current.ino()) != (expected.dev(), expected.ino())
        || cmdline(child)? != cmdline(coordinator)?
        || !status.lines().any(|l| l.starts_with("State:\tS"))
        || fields.len() < 4
        || fields[0].parse::<i64>().ok() != Some(nix::libc::SYS_recvfrom)
        || u64::from_str_radix(fields[3].trim_start_matches("0x"), 16).ok() != Some(1)
    {
        bail!("controller is not provably blocked on its unreleased one-byte native gate");
    }
    let fd = u64::from_str_radix(fields[1].trim_start_matches("0x"), 16)?;
    if !fs::read_link(format!("/proc/{child}/fd/{fd}"))?
        .as_os_str()
        .as_encoded_bytes()
        .starts_with(b"socket:[")
    {
        bail!("controller gate descriptor is not a native socket");
    }
    Ok(child)
}
