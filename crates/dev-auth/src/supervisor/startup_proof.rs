//! Kernel-authenticated readiness from an installed monitor under an owned spawn.
use super::*;
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

// Linux asm-generic socket UAPI used by x86_64/aarch64. Unknown kernels fail the
// option call; cached socketpair creator credentials are never a substitute.
const SO_PASSPIDFD: nix::libc::c_int = 76;
const SCM_PIDFD: nix::libc::c_int = 4;
const PROC_LIMIT: u64 = 64 * 1024;
const MAX_LINEAGE: usize = 128;

pub(crate) struct SpawnAuthority {
    pub parent_pid: u32,
    pub parent_pidfd: OwnedFd,
    pub image: File,
    pub cgroup: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

pub(crate) struct RootSpawnOwner {
    pid: u32,
    pidfd: OwnedFd,
    image: File,
    cgroup: PathBuf,
    uid: u32,
    gid: u32,
    parent_pid: u32,
    parent_pidfd: OwnedFd,
}

pub(crate) struct Proof {
    pid: u32,
    pidfd: OwnedFd,
    image: File,
    lineage: Vec<OwnedFd>,
}

pub(crate) fn pair() -> Result<(OwnedFd, OwnedFd)> {
    if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        bail!("kernel-authenticated startup proof is unavailable on this target");
    }
    let (reader, writer) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    nix::sys::socket::setsockopt(&reader, sockopt::PassCred, &true)?;
    let enabled: nix::libc::c_int = 1;
    // SAFETY: a live socket and initialized scalar option are valid for this
    // synchronous call. The kernel must support atomic per-message sender FDs.
    if unsafe {
        nix::libc::setsockopt(
            reader.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            SO_PASSPIDFD,
            (&enabled as *const nix::libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as nix::libc::socklen_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("require atomic kernel startup sender custody");
    }
    let reader = crate::supervisor_descriptors::normalize_source_descriptor(File::from(reader))?;
    let writer = crate::supervisor_descriptors::normalize_source_descriptor(File::from(writer))?;
    Ok((reader.into(), writer.into()))
}

impl RootSpawnOwner {
    pub(crate) fn from_authenticated_spawn(
        pidfd: OwnedFd,
        authority: SpawnAuthority,
    ) -> Result<Self> {
        let pid = pidfd_pid(&pidfd)?;
        if pid == 0
            || pidfd_pid(&authority.parent_pidfd)? != authority.parent_pid
            || !crate::linux_admission::pidfd_process_is_alive(&pidfd)?
            || !crate::linux_admission::pidfd_process_is_alive(&authority.parent_pidfd)?
            || parent_pid(pid)? != authority.parent_pid
            || crate::linux_admission::read_unified_cgroup(pid)? != authority.cgroup
        {
            bail!("startup spawn owner differs from its authenticated native parent");
        }
        Ok(Self {
            pid,
            pidfd,
            image: authority.image,
            cgroup: authority.cgroup,
            uid: authority.uid,
            gid: authority.gid,
            parent_pid: authority.parent_pid,
            parent_pidfd: authority.parent_pidfd,
        })
    }

    fn verify(&self, message: Message) -> Result<Proof> {
        if message.credentials.uid != self.uid || message.credentials.gid != self.gid {
            bail!("startup proof crossed its admitted native identity");
        }
        let pid = u32::try_from(message.credentials.pid)
            .context("kernel startup sender PID is invalid")?;
        if pid == 0 || pidfd_pid(&message.pidfd)? != pid {
            bail!("startup proof sender credentials and pidfd differ");
        }
        let image = File::open(format!("/proc/{pid}/exe"))
            .context("retain installed startup monitor image")?;
        let mut proof = Proof {
            pid,
            pidfd: message.pidfd,
            image,
            lineage: Vec::new(),
        };
        // Every ancestor is retained and each relationship is repeated after
        // retention. No submitted PID or same-UID/same-image shortcut is used.
        let mut current = pid;
        for _ in 0..MAX_LINEAGE {
            if current == self.pid {
                proof.recheck(self)?;
                return Ok(proof);
            }
            let parent = parent_pid(current)?;
            if parent == 0 || parent == current {
                break;
            }
            let retained = rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(parent as i32)
                    .context("startup ancestry PID is invalid")?,
                rustix::process::PidfdFlags::empty(),
            )?;
            if parent_pid(current)? != parent
                || !crate::linux_admission::pidfd_process_is_alive(&retained)?
            {
                bail!("startup monitor ancestry changed during retention");
            }
            proof.lineage.push(retained);
            current = parent;
        }
        bail!("startup proof sender is outside its retained native spawn lineage")
    }
}

impl Proof {
    pub(crate) fn recheck(&self, owner: &RootSpawnOwner) -> Result<()> {
        if !crate::linux_admission::pidfd_process_is_alive(&owner.pidfd)?
            || !crate::linux_admission::pidfd_process_is_alive(&owner.parent_pidfd)?
            || parent_pid(owner.pid)? != owner.parent_pid
            || !crate::linux_admission::pidfd_process_is_alive(&self.pidfd)?
            || self.lineage.iter().any(|ancestor| {
                !crate::linux_admission::pidfd_process_is_alive(ancestor).unwrap_or(false)
            })
            || crate::linux_admission::read_unified_cgroup(self.pid)? != owner.cgroup
        {
            bail!("retained startup monitor or ancestry is no longer admitted");
        }
        let expected = owner.image.metadata()?;
        let retained = self.image.metadata()?;
        let current = File::open(format!("/proc/{}/exe", self.pid))?.metadata()?;
        if !retained.file_type().is_file()
            || retained.uid() != 0
            || retained.mode() & 0o022 != 0
            || (expected.dev(), expected.ino()) != (retained.dev(), retained.ino())
            || (current.dev(), current.ino()) != (retained.dev(), retained.ino())
        {
            bail!("startup monitor lost its exact installed-core identity");
        }
        Ok(())
    }
}

fn parent_pid(pid: u32) -> Result<u32> {
    let mut bytes = String::new();
    File::open(format!("/proc/{pid}/stat"))?
        .take(PROC_LIMIT + 1)
        .read_to_string(&mut bytes)?;
    if bytes.len() as u64 > PROC_LIMIT {
        bail!("startup ancestry record exceeds its bound");
    }
    let fields = bytes
        .rsplit_once(") ")
        .context("startup ancestry record is invalid")?
        .1;
    fields
        .split_whitespace()
        .nth(1)
        .context("startup ancestry parent is missing")?
        .parse()
        .context("startup ancestry parent is invalid")
}

fn pidfd_pid(pidfd: &OwnedFd) -> Result<u32> {
    let mut bytes = String::new();
    File::open(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut bytes)?;
    if bytes.len() > 4096 {
        bail!("startup sender pidfd record exceeds its bound");
    }
    let mut pids = bytes.lines().filter_map(|line| line.strip_prefix("Pid:\t"));
    let pid = pids
        .next()
        .context("startup sender is not a native pidfd")?
        .parse()?;
    if pids.next().is_some() {
        bail!("startup sender pidfd identity is ambiguous");
    }
    Ok(pid)
}

struct Message {
    byte: u8,
    credentials: nix::libc::ucred,
    pidfd: OwnedFd,
}

// An aligned bounded buffer accommodates credentials, the kernel sender pidfd,
// and any delivered unexpected rights. Every received FD is owned before errors.
fn receive(reader: &OwnedFd) -> Result<Option<Message>> {
    let mut bytes = [0_u8; 2];
    let mut control = [0_usize; 64];
    let mut iov = nix::libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: msghdr is native POD; every pointer below names its initialized
    // live output buffer, and recvmsg retains none beyond this synchronous call.
    let mut header: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = std::mem::size_of_val(&control);
    let received = unsafe {
        nix::libc::recvmsg(
            reader.as_raw_fd(),
            &mut header,
            nix::libc::MSG_DONTWAIT | nix::libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Ok(None);
        }
        return Err(error).context("receive native startup sender proof");
    }
    let mut credentials = None;
    let mut sender = None;
    let mut unexpected = false;
    // SAFETY: CMSG traversal starts from the bounded kernel-filled buffer; each
    // data extent is checked before unaligned reads. No received FD is borrowed.
    unsafe {
        let mut cmsg = nix::libc::CMSG_FIRSTHDR(&header);
        while !cmsg.is_null() {
            let offset = cmsg as usize - control.as_ptr() as usize;
            let length = (*cmsg).cmsg_len;
            let prefix = nix::libc::CMSG_LEN(0) as usize;
            if length < prefix
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > header.msg_controllen)
            {
                bail!("native startup ancillary frame is invalid");
            }
            let data = nix::libc::CMSG_DATA(cmsg);
            let data_len = length - prefix;
            match ((*cmsg).cmsg_level, (*cmsg).cmsg_type) {
                (nix::libc::SOL_SOCKET, nix::libc::SCM_CREDENTIALS)
                    if data_len == std::mem::size_of::<nix::libc::ucred>() =>
                {
                    if credentials
                        .replace(std::ptr::read_unaligned(data.cast()))
                        .is_some()
                    {
                        unexpected = true;
                    }
                }
                (nix::libc::SOL_SOCKET, SCM_PIDFD | nix::libc::SCM_RIGHTS) => {
                    if !data_len.is_multiple_of(std::mem::size_of::<RawFd>()) {
                        unexpected = true;
                    }
                    for index in 0..data_len / std::mem::size_of::<RawFd>() {
                        let fd: RawFd = std::ptr::read_unaligned(
                            data.add(index * std::mem::size_of::<RawFd>()).cast(),
                        );
                        if fd < 0 {
                            unexpected = true;
                            continue;
                        }
                        let owned = OwnedFd::from_raw_fd(fd);
                        if (*cmsg).cmsg_type == SCM_PIDFD
                            && data_len == std::mem::size_of::<RawFd>()
                            && sender.is_none()
                        {
                            sender = Some(owned);
                        } else {
                            unexpected = true;
                            drop(owned);
                        }
                    }
                }
                _ => unexpected = true,
            }
            cmsg = nix::libc::CMSG_NXTHDR(&header, cmsg);
        }
    }
    if received != 1
        || header.msg_flags & (nix::libc::MSG_TRUNC | nix::libc::MSG_CTRUNC) != 0
        || unexpected
    {
        bail!("native startup proof has an invalid exact frame");
    }
    Ok(Some(Message {
        byte: bytes[0],
        credentials: credentials.context("native startup proof lacks sender credentials")?,
        pidfd: sender.context("native startup proof lacks atomic sender pidfd")?,
    }))
}

pub(crate) fn await_ready(reader: &OwnedFd, owner: &RootSpawnOwner) -> Result<Proof> {
    let deadline = Instant::now() + STARTUP_PROOF_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            bail!("kernel-authenticated startup proof timed out");
        }
        let mut poller = [PollFd::new(
            reader.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        poll(&mut poller, PollTimeout::from(20_u16))?;
        let Some(message) = receive(reader)? else {
            continue;
        };
        if message.byte != 1 {
            bail!("configured workload did not prove its final exec");
        }
        return owner.verify(message);
    }
}

pub(crate) fn validate_writer(file: &File) -> Result<()> {
    if file.as_raw_fd() < 3 || getsockopt(file, sockopt::SockType)? != SockType::SeqPacket {
        bail!("startup proof requires a retained native seqpacket socket");
    }
    Ok(())
}

pub(crate) fn validate_release_writer(release: &OwnedFd) -> Result<()> {
    let file = File::from(rustix::io::fcntl_dupfd_cloexec(release, 3)?);
    let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)?;
    if !file.metadata()?.file_type().is_fifo()
        || flags & nix::libc::O_ACCMODE != nix::libc::O_WRONLY
        || flags & nix::libc::O_NONBLOCK == 0
    {
        bail!("bootstrap release requires a retained write-only pipe");
    }
    Ok(())
}

pub(crate) fn send_byte(socket: &File, byte: u8) -> Result<()> {
    use nix::sys::socket::{send, MsgFlags};
    if send(
        socket.as_raw_fd(),
        &[byte],
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
    )? != 1
    {
        bail!("private startup message was not sent exactly");
    }
    Ok(())
}

pub(crate) fn await_release_witness(
    socket: &OwnedFd,
    owner: &RootSpawnOwner,
    proof: &Proof,
) -> Result<()> {
    let deadline = Instant::now() + STARTUP_PROOF_TIMEOUT;
    loop {
        proof.recheck(owner)?;
        if Instant::now() >= deadline {
            bail!("native release witness timed out");
        }
        let mut poller = [PollFd::new(
            socket.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        poll(&mut poller, PollTimeout::from(20_u16))?;
        let Some(message) = receive(socket)? else {
            continue;
        };
        if message.byte != 3
            || message.credentials.pid as u32 != proof.pid
            || message.credentials.uid != owner.uid
            || message.credentials.gid != owner.gid
            || pidfd_pid(&message.pidfd)? != proof.pid
        {
            bail!("native release witness differs from the retained ready monitor");
        }
        proof.recheck(owner)?;
        return Ok(());
    }
}

pub(crate) fn send_commit_receipt(socket: &OwnedFd) -> Result<()> {
    let file = File::from(rustix::io::fcntl_dupfd_cloexec(socket, 3)?);
    send_byte(&file, 4)
}

pub(crate) fn await_commit_receipt(socket: &File) -> Result<()> {
    let deadline = Instant::now() + STARTUP_PROOF_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            bail!("release commit receipt timed out");
        }
        let mut poller = [PollFd::new(
            socket.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        poll(&mut poller, PollTimeout::from(20_u16))?;
        let mut bytes = [0_u8; 2];
        match nix::sys::socket::recv(
            socket.as_raw_fd(),
            &mut bytes,
            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(1) if bytes[0] == 4 => return Ok(()),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            _ => bail!("release commit receipt was absent or invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr};
    use std::io::IoSlice;

    const FIXTURE: &str = "DEV_AUTH_TEST_STARTUP_SENDER_FIXTURE";
    const FIXTURE_FD: &str = "DEV_AUTH_TEST_STARTUP_SENDER_FD";
    const TEST: &str =
        "supervisor::startup_proof::tests::entry_window_foreign_sender_cannot_spoof_owned_monitor";

    struct ChildGuard(Child);
    impl std::ops::Deref for ChildGuard {
        type Target = Child;
        fn deref(&self) -> &Child {
            &self.0
        }
    }
    impl std::ops::DerefMut for ChildGuard {
        fn deref_mut(&mut self) -> &mut Child {
            &mut self.0
        }
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn fixture(mode: &str, writer: Option<&OwnedFd>) -> ChildGuard {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", TEST]).env(FIXTURE, mode);
        if let Some(writer) = writer {
            let fd = writer.as_raw_fd();
            command.env(FIXTURE_FD, fd.to_string());
            // SAFETY: retain only this already-owned descriptor in the child;
            // no compact mapping can overwrite spawn's private error endpoint.
            unsafe {
                command.pre_exec(move || {
                    if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        ChildGuard(command.spawn().unwrap())
    }

    #[test]
    fn entry_window_foreign_sender_cannot_spoof_owned_monitor() {
        if let Ok(mode) = std::env::var(FIXTURE) {
            if mode == "borrowed-entry-window" {
                let fd = std::env::var(FIXTURE_FD).unwrap().parse::<RawFd>().unwrap();
                // SAFETY: the isolated fixture retained this sole FD across exec.
                let writer = unsafe { OwnedFd::from_raw_fd(fd) };
                assert_eq!(nix::unistd::write(&writer, &[1]).unwrap(), 1);
                thread::sleep(Duration::from_secs(10));
                return;
            }
            if mode == "owned-monitor" {
                thread::sleep(Duration::from_secs(10));
                return;
            }
            panic!("unknown isolated startup fixture");
        }
        let (reader, writer) = pair().unwrap();
        let mut monitor = fixture("owned-monitor", None);
        let pid = rustix::process::Pid::from_raw(monitor.id() as i32).unwrap();
        let owner = RootSpawnOwner::from_authenticated_spawn(
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap(),
            SpawnAuthority {
                parent_pid: std::process::id(),
                parent_pidfd: rustix::process::pidfd_open(
                    rustix::process::getpid(),
                    rustix::process::PidfdFlags::empty(),
                )
                .unwrap(),
                image: File::open("/proc/self/exe").unwrap(),
                cgroup: crate::linux_admission::read_unified_cgroup(std::process::id()).unwrap(),
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
            },
        )
        .unwrap();
        // Deliberately disclose the writer before monitor protection. The kernel
        // still attributes writes to this foreign same-UID/same-image sibling.
        let mut foreign = fixture("borrowed-entry-window", Some(&writer));
        let deadline = Instant::now() + Duration::from_secs(5);
        let received = loop {
            assert!(
                Instant::now() < deadline,
                "foreign sender fixture did not respond"
            );
            if let Some(received) = receive(&reader).unwrap() {
                break received;
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(received.credentials.pid as u32, foreign.id());
        assert_eq!(pidfd_pid(&received.pidfd).unwrap(), foreign.id());
        assert_ne!(foreign.id(), monitor.id());
        let error = owner.verify(received).err().unwrap().to_string();
        assert!(error.contains("lineage"), "unexpected denial: {error}");
        foreign.kill().unwrap();
        foreign.wait().unwrap();
        monitor.kill().unwrap();
        monitor.wait().unwrap();
    }

    #[test]
    fn unexpected_native_rights_are_closed_before_proof_rejection() {
        let (reader, writer) = pair().unwrap();
        let (pipe_reader, pipe_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK)
                .unwrap();
        let rights = [pipe_writer.as_raw_fd()];
        sendmsg::<UnixAddr>(
            writer.as_raw_fd(),
            &[IoSlice::new(&[1])],
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        drop(pipe_writer);
        assert!(receive(&reader).is_err());
        let mut byte = [0_u8];
        assert_eq!(nix::unistd::read(&pipe_reader, &mut byte).unwrap(), 0);
    }
}
