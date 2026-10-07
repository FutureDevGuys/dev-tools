//! Finite collector-negative fixture. The VM/kernel and collector profile must
//! already be explicitly provisioned; no sysctl, collector or policy is installed.
use super::privilege_native_faults as fault;
use anyhow::{bail, Context, Result};
use dev_auth::privilege::{custody, policy};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::ExitStatusExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
const BASE: &str = "/run/dev-auth-core-fixture";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    kernel_release: String,
    collector: PathBuf,
    collector_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    crashed_pid: i32,
    collector_pid: i32,
}
fn configuration() -> Result<(Configuration, Vec<u8>)> {
    if nix::unistd::getuid().as_raw() != 0
        || nix::unistd::geteuid().as_raw() != 0
        || !Path::new("/run/.containerenv").is_file()
        || fs::read_to_string("/proc/1/comm")?.trim() != "systemd"
    {
        bail!("collector fixture requires explicitly prepared disposable native root");
    }
    let bytes = custody::read_document(&Path::new(BASE).join("configuration.json"), 0, 0o600)?;
    let config: Configuration = policy::parse(&bytes)?;
    if config.schema != "dev-auth-native-core-collector-v1"
        || config.kernel_release != fs::read_to_string("/proc/sys/kernel/osrelease")?.trim()
        || config.collector != std::env::current_exe()?
    {
        bail!("exact native kernel/collector identity differs");
    }
    custody::held_root_executable(&config.collector, &config.collector_sha256)?;
    let expected = format!(
        "|{} core-collector %P\n",
        config
            .collector
            .to_str()
            .context("collector path not UTF-8")?
    );
    if fs::read("/proc/sys/kernel/core_pattern")? != expected.as_bytes() {
        bail!("already configured finite collector profile required");
    }
    let root = fs::symlink_metadata(BASE)?;
    if !root.is_dir() || root.uid() != 0 || root.mode() & 0o7777 != 0o700 {
        bail!("collector state lacks private root custody");
    }
    Ok((config, bytes))
}
fn event_file(write: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(write)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(Path::new(BASE).join("events"))?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > 64 * 1024
    {
        bail!("collector events custody invalid");
    }
    Ok(file)
}
fn check_before(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        bail!("collector fixture milestone timed out");
    }
    Ok(())
}
fn pause() {
    std::thread::sleep(Duration::from_millis(5));
}
fn dead(fd: &OwnedFd) -> Result<bool> {
    let mut p = nix::libc::pollfd {
        fd: fd.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { nix::libc::poll(&mut p, 1, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(n > 0 && p.revents & nix::libc::POLLIN != 0)
}
/// Only the preconfigured kernel handler writes this protected log. It waits
/// for the root observer's acknowledgement so its pidfd can be retained before
/// exit. No core contents are read or persisted.
pub fn collect(pid: &str) -> Result<()> {
    configuration()?;
    let pid: i32 = pid.parse()?;
    if pid <= 1 {
        bail!("invalid kernel host PID");
    }
    let me = nix::unistd::getpid().as_raw();
    let mut file = event_file(true)?;
    if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    file.write_all(&policy::canonical(&Event {
        crashed_pid: pid,
        collector_pid: me,
    })?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_UN) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let ack = Path::new(BASE).join(format!("ack-{me}"));
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if custody::read_document(&ack, 0, 0o600).ok().as_deref()
            == Some(pid.to_string().as_bytes())
        {
            break;
        }
        check_before(until)?;
        pause();
    }
    Ok(())
}
pub fn positive() -> Result<()> {
    configuration()?;
    let zero = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &zero) } != 0
        || unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    crash();
}
fn crash() -> ! {
    unsafe {
        nix::libc::signal(nix::libc::SIGSEGV, nix::libc::SIG_DFL);
        nix::libc::raise(nix::libc::SIGSEGV);
        nix::libc::_exit(126)
    }
}

pub fn assert_filter() -> Result<()> {
    let mut actual = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_CORE, &mut actual) } != 0
        || actual.rlim_cur != 1
        || actual.rlim_max != 1
    {
        bail!("exact core limit did not survive exec");
    }
    for high in [0, 1u64 << 32, 0xffff_ffff_0000_0000] {
        let resource = high | nix::libc::RLIMIT_CORE as u64;
        for limit in [0, 1, nix::libc::RLIM_INFINITY] {
            let proposed = nix::libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            let n = unsafe { nix::libc::syscall(nix::libc::SYS_setrlimit, resource, &proposed) };
            if n != -1 || std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::EPERM) {
                bail!("setrlimit core write bypassed inherited filter");
            }
            for pid in [0, nix::unistd::getpid().as_raw()] {
                let n = unsafe {
                    nix::libc::syscall(
                        nix::libc::SYS_prlimit64,
                        pid,
                        resource,
                        &proposed,
                        std::ptr::null_mut::<nix::libc::rlimit>(),
                    )
                };
                if n != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::EPERM)
                {
                    bail!("prlimit core write bypassed inherited filter");
                }
            }
        }
        // A high-only nonnull pointer must be denied, not passed to the kernel
        // to return EFAULT; null-new-limit read-only queries must still work.
        let n = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_prlimit64,
                0,
                resource,
                1u64 << 32,
                std::ptr::null_mut::<nix::libc::rlimit>(),
            )
        };
        if n != -1 || std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::EPERM) {
            bail!("full-width new-limit pointer bypassed filter");
        }
        let n = unsafe {
            nix::libc::syscall(nix::libc::SYS_prlimit64, 0, resource, 0usize, &mut actual)
        };
        if n != 0 || actual.rlim_cur != 1 || actual.rlim_max != 1 {
            bail!("read-only core query failed");
        }
    }
    Ok(())
}
pub fn selftest() -> Result<()> {
    dev_auth::privilege::sandbox::native_fixture_lock_core()?;
    assert_filter()?;
    let status = Command::new(std::env::current_exe()?)
        .arg("core-filter-child")
        .status()?;
    if !status.success() {
        bail!("core guard failed across fork/exec");
    }
    Ok(())
}
fn checkpoint(path: &Path, role: &str) -> Result<()> {
    let root = path.parent().context("fixture scope absent")?;
    let directory = File::open(root)?;
    fault::write_at(&directory, &format!("core-ready-{role}"), role.as_bytes())?;
    let until = Instant::now() + Duration::from_secs(5);
    let release = root.join(format!("core-release-{role}"));
    loop {
        if fs::read(&release).ok().as_deref() == Some(role.as_bytes()) {
            break;
        }
        check_before(until)?;
        pause();
    }
    Ok(())
}
pub fn descendant(path: &Path) -> Result<()> {
    assert_filter()?;
    checkpoint(path, "descendant")?;
    crash()
}
pub fn payload(path: &Path) -> Result<()> {
    assert_filter()?;
    let status = Command::new(std::env::current_exe()?)
        .arg("core-descendant")
        .arg(path)
        .status()?;
    if status.signal() != Some(nix::libc::SIGSEGV) || status.core_dumped() {
        bail!("descendant core suppression/native status differs");
    }
    assert_filter()?;
    checkpoint(path, "direct")?;
    crash()
}

pub struct Proof {
    config: Configuration,
    config_bytes: Vec<u8>,
    events: File,
    identity: (u64, u64),
    negatives: Vec<(i32, OwnedFd)>,
    positives: Vec<i32>,
}
impl Proof {
    pub fn prepare() -> Result<Self> {
        let (config, config_bytes) = configuration()?;
        let events = event_file(false)?;
        let m = events.metadata()?;
        if m.len() != 0 {
            bail!("fresh empty collector event file required");
        }
        let mut proof = Self {
            config,
            config_bytes,
            events,
            identity: (m.dev(), m.ino()),
            negatives: vec![],
            positives: vec![],
        };
        proof.positive_control()?;
        Ok(proof)
    }
    fn records(&self) -> Result<Vec<Event>> {
        use std::os::unix::fs::FileExt;
        let current = event_file(false)?;
        if unsafe { nix::libc::flock(current.as_raw_fd(), nix::libc::LOCK_SH) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let m = current.metadata()?;
        if (m.dev(), m.ino()) != self.identity || configuration()?.1 != self.config_bytes {
            bail!("collector proof custody/profile changed");
        }
        let mut bytes = vec![0u8; m.len() as usize];
        self.events.read_exact_at(&mut bytes, 0)?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bail!("collector event incomplete");
        }
        bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(policy::parse)
            .collect()
    }
    fn positive_control(&mut self) -> Result<()> {
        let mut child = Command::new(&self.config.collector)
            .arg("core-positive")
            .spawn()?;
        let pid = i32::try_from(child.id())?;
        let child_fd = fault::pidfd(pid)?;
        let until = Instant::now() + Duration::from_secs(5);
        let event = loop {
            if let Some(e) = self.records()?.into_iter().find(|e| e.crashed_pid == pid) {
                break e;
            }
            check_before(until)?;
            pause();
        };
        let collector = fault::pidfd(event.collector_pid)?;
        let image = fs::metadata(&self.config.collector)?;
        let live = fs::metadata(format!("/proc/{}/exe", event.collector_pid))?;
        let expected = format!(
            "{}\0core-collector\0{pid}\0",
            self.config.collector.to_str().context("UTF-8 required")?
        );
        if (image.dev(), image.ino()) != (live.dev(), live.ino())
            || fs::read(format!("/proc/{}/cmdline", event.collector_pid))? != expected.as_bytes()
        {
            bail!("positive collector lacks exact held identity");
        }
        custody::write_new_document(
            &Path::new(BASE).join(format!("ack-{}", event.collector_pid)),
            pid.to_string().as_bytes(),
            0,
        )?;
        while !dead(&collector)? || !dead(&child_fd)? {
            check_before(until)?;
            pause();
        }
        if child.wait()?.signal() != Some(nix::libc::SIGSEGV) {
            bail!("positive native crash differs");
        }
        self.positives.push(pid);
        Ok(())
    }
    pub fn retain(&mut self, pid: i32) -> Result<()> {
        if self.negatives.iter().any(|(p, _)| *p == pid) {
            return Ok(());
        }
        let fd = fault::pidfd(pid)?;
        if fs::metadata(format!("/proc/{pid}"))?.uid() != 0 {
            bail!("negative core target is not native root");
        }
        let limits = fs::read_to_string(format!("/proc/{pid}/limits"))?;
        let core = limits
            .lines()
            .find_map(|l| l.strip_prefix("Max core file size"))
            .context("core limit observation absent")?
            .split_whitespace()
            .collect::<Vec<_>>();
        if core != ["1", "1", "bytes"] {
            bail!("trusted/payload core limit differs");
        }
        self.negatives.push((pid, fd));
        Ok(())
    }
    pub fn finish(mut self) -> Result<()> {
        if self.negatives.is_empty() {
            bail!("no retained native-negative subjects");
        }
        let until = Instant::now() + Duration::from_secs(8);
        for (_, fd) in &self.negatives {
            while !dead(fd)? {
                check_before(until)?;
                pause();
            }
        }
        self.positive_control()?;
        let records = self.records()?;
        if records.len() != self.positives.len()
            || records
                .iter()
                .any(|e| !self.positives.contains(&e.crashed_pid))
        {
            bail!("negative subject invoked the out-of-domain core collector");
        }
        Ok(())
    }
}

pub fn payload_driver(
    input: &super::privilege_native_contract::Input,
    root: &File,
    mut proof: Proof,
) -> Result<()> {
    fault::write_at(root, "fault-driver-ready", input.case.name().as_bytes())?;
    let until = Instant::now() + Duration::from_secs(150);
    let session = loop {
        if let Ok(b) = fault::read_at(root, "session") {
            if let Ok(s) = String::from_utf8(b) {
                if dev_auth::privilege::protocol::token(&s).is_ok() {
                    break s;
                }
            }
        }
        check_before(until)?;
        pause();
    };
    let unit = PathBuf::from(format!(
        "/sys/fs/cgroup/system.slice/dev-auth-maintenance-{session}.service"
    ));
    let scope = File::open(input.fixture_root.join("scope"))?;
    let image = fs::metadata(&input.fixture_binary)?;
    for role in ["descendant", "direct"] {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if fault::read_at(&scope, &format!("core-ready-{role}"))
                .ok()
                .as_deref()
                == Some(role.as_bytes())
            {
                break;
            }
            check_before(deadline)?;
            pause();
        }
        // Never trust a payload PID-namespace number. Resolve the unique native
        // host PID from this retained service's operation domain and exact image/argv.
        let expected = if role == "descendant" {
            vec![
                input.fixture_binary.as_os_str().as_encoded_bytes().to_vec(),
                b"core-descendant".to_vec(),
                input
                    .fixture_root
                    .join("scope/core")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ]
        } else {
            vec![
                input.fixture_binary.as_os_str().as_encoded_bytes().to_vec(),
                b"helper".to_vec(),
                b"core-probe".to_vec(),
                input
                    .fixture_root
                    .join("scope/core")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ]
        };
        let mut matches = 0;
        for entry in fs::read_dir(&unit)? {
            let entry = entry?;
            if entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b"operation-")
            {
                for target in fault::pids(&entry.path())? {
                    proof.retain(target)?;
                    let actual = fs::metadata(format!("/proc/{target}/exe"))?;
                    let bytes = fs::read(format!("/proc/{target}/cmdline"))?;
                    let args = bytes
                        .split(|b| *b == 0)
                        .filter(|b| !b.is_empty())
                        .map(<[u8]>::to_vec)
                        .collect::<Vec<_>>();
                    if (actual.dev(), actual.ino()) == (image.dev(), image.ino())
                        && args == expected
                    {
                        matches += 1;
                    }
                }
            }
        }
        if matches != 1 {
            bail!("negative core subject lacks unique host PID/image/argv/domain identity");
        }
        fault::write_at(&scope, &format!("core-release-{role}"), role.as_bytes())?;
    }
    fault::write_at(root, "fault-applied", input.case.name().as_bytes())?;
    while fault::read_at(root, "observer-cleanup").ok().as_deref() != Some(session.as_bytes()) {
        check_before(until)?;
        pause();
    }
    proof.finish()?;
    fault::write_at(root, "fault-driver-passed", input.case.name().as_bytes())?;
    Ok(())
}
