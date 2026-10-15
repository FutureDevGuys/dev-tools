use crate::packet::{receive_owned, Packet, FRAME_LIMIT};
use crate::sudo_wire::{Decision, Message, Request, Response, SUDO_HELLO, SUDO_SCHEMA};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{self, MsgFlags, SockFlag, SockType, UnixAddr};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) static STATE: Mutex<Option<State>> = Mutex::new(None);

pub(crate) struct State {
    pub uid: u32,
    pub user: Vec<u8>,
    pub client: Option<Client>,
    pub admitted: bool,
    pub relay: bool,
    pub frontend: PathBuf,
    pub runtime: PathBuf,
}

pub(crate) struct Client {
    socket: OwnedFd,
    coordinator: OwnedFd,
    deadline: Duration,
    grant: String,
}

pub(crate) fn initialize(user_info: &[OsString], options: &[OsString]) -> io::Result<State> {
    let uid = field(user_info, b"uid")?
        .to_str()
        .ok_or_else(invalid)?
        .parse::<u32>()
        .map_err(|_| invalid())?;
    let user = field(user_info, b"user")?.as_bytes().to_vec();
    if user.is_empty() || user.len() > 256 || !nix::unistd::Uid::effective().is_root() {
        return Err(denied());
    }
    let mut runtime = PathBuf::from("/run/dev-auth-grants");
    let mut frontend = PathBuf::from("/usr/local/bin/dev-auth");
    let mut keys = std::collections::BTreeSet::new();
    for option in options {
        let bytes = option.as_bytes();
        let position = bytes
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(invalid)?;
        let (key, tail) = bytes.split_at(position);
        if !keys.insert(key) {
            return Err(invalid());
        }
        let value = PathBuf::from(OsStr::from_bytes(&tail[1..]));
        match key {
            b"runtime" => runtime = value,
            b"frontend" => frontend = value,
            _ => return Err(invalid()),
        }
    }
    if !runtime.is_absolute() || !frontend.is_absolute() {
        return Err(invalid());
    }
    let mut state = State {
        uid,
        user,
        client: None,
        admitted: false,
        relay: false,
        frontend,
        runtime: runtime.clone(),
    };
    if uid == 0 {
        return Ok(state);
    }
    let routing = managed_routing(&runtime, uid)?;
    let path = runtime.join("sudo.sock");
    match protected(&path, false) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound && !routing => return Ok(state),
        Err(error) => return Err(error),
    }
    let socket = socket::socket(
        socket::AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    if let Err(error) = socket::connect(socket.as_raw_fd(), &UnixAddr::new(&path)?) {
        // An installed but unavailable service cannot revoke ordinary native
        // behavior for an unselected account. Selected routing always denies.
        if !routing
            && matches!(
                error,
                nix::errno::Errno::ECONNREFUSED | nix::errno::Errno::ENOENT
            )
        {
            return Ok(state);
        }
        return Err(error.into());
    }
    let peer = socket::getsockopt(&socket, socket::sockopt::PeerCredentials)?;
    let coordinator = socket::getsockopt(&socket, socket::sockopt::PeerPidfd)?;
    if peer.uid() != 0 || !quiet(&coordinator)? {
        return Err(denied());
    }
    let mut client = Client {
        socket,
        coordinator,
        deadline: Duration::ZERO,
        grant: String::new(),
    };
    let hello = client.receive(Instant::now() + Duration::from_secs(3))?;
    if hello.bytes != SUDO_HELLO || !hello.descriptors.is_empty() {
        return Err(invalid());
    }
    let (response, descriptors) = client.exchange(Request::Preflight { uid })?;
    if !descriptors.is_empty() {
        return Err(invalid());
    }
    match response.decision {
        Decision::Native if !routing => return Ok(state),
        Decision::Managed => {}
        Decision::Relay => state.relay = true,
        _ => return Err(denied()),
    }
    client.deadline = Duration::from_millis(response.hard_deadline_milliseconds);
    client.grant = response.grant.ok_or_else(invalid)?;
    if client.grant.len() != 32
        || !client
            .grant
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    if boot_time()? >= client.deadline {
        return Err(denied());
    }
    state.client = Some(client);
    Ok(state)
}

/// Replace the namespace-local sudo process with an unprivileged product
/// frontend. The root coordinator then executes its held host sudo image as
/// this original user. Native sudo still owns all parsing and final policy.
pub(crate) fn relay(
    state: &State,
    user_info: &[OsString],
    arguments: Vec<OsString>,
    environment: Vec<OsString>,
) -> io::Error {
    use std::os::unix::process::CommandExt;
    let prepared = (|| -> io::Result<std::process::Command> {
        // The public executable is commonly a root-owned receipt alias. Only
        // its final symlink may resolve; the link's parent and target remain
        // native root-owned authority, never a user-writable redirect.
        let link = std::fs::symlink_metadata(&state.frontend)?;
        if link.uid() != 0 {
            return Err(denied());
        }
        let _parent = protected(state.frontend.parent().ok_or_else(denied)?, true)?;
        let frontend = std::fs::canonicalize(&state.frontend)?;
        let executable = protected(&frontend, false)?;
        let metadata = executable.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 || arguments.is_empty() {
            return Err(denied());
        }
        let gid = field(user_info, b"gid")?
            .to_str()
            .ok_or_else(invalid)?
            .parse::<u32>()
            .map_err(|_| invalid())?;
        let groups = field(user_info, b"groups")?
            .to_str()
            .ok_or_else(invalid)?
            .split(',')
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u32>().map_err(|_| invalid()))
            .collect::<io::Result<Vec<_>>>()?;
        if groups.len() > 65_536 {
            return Err(invalid());
        }
        let mut command = std::process::Command::new(&frontend);
        command
            .arg("grant-sudo-relay")
            .arg(&state.client.as_ref().ok_or_else(invalid)?.grant)
            .arg("--")
            .args(arguments)
            .env_clear();
        for variable in environment {
            let bytes = variable.as_bytes();
            let position = bytes
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or_else(invalid)?;
            let (name, tail) = bytes.split_at(position);
            command.env(OsStr::from_bytes(name), OsStr::from_bytes(&tail[1..]));
        }
        command.env("DEV_AUTH_GRANT_SOCKET", state.runtime.join("control.sock"));
        command
            .env_remove("DEV_AUTH_GH_CHILD")
            .env_remove("DEV_AUTH_GIT_CHILD");
        nix::unistd::setgroups(
            &groups
                .into_iter()
                .map(nix::unistd::Gid::from_raw)
                .collect::<Vec<_>>(),
        )?;
        let gid = nix::unistd::Gid::from_raw(gid);
        nix::unistd::setresgid(gid, gid, gid)?;
        let uid = nix::unistd::Uid::from_raw(state.uid);
        nix::unistd::setresuid(uid, uid, uid)?;
        Ok(command)
    })();
    match prepared {
        Ok(mut command) => command.exec(),
        Err(error) => error,
    }
}

impl Client {
    fn receive(&self, deadline: Instant) -> io::Result<Packet> {
        loop {
            if !quiet(&self.coordinator)? {
                return Err(denied());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
            let mut descriptor = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
            match poll(
                &mut descriptor,
                PollTimeout::try_from(remaining).map_err(|_| invalid())?,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
                Ok(_) => return receive_owned(&self.socket),
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn exchange(&mut self, request: Request) -> io::Result<(Response, Vec<OwnedFd>)> {
        let request = serde_json::to_vec(&Message {
            schema: SUDO_SCHEMA.to_owned(),
            request,
        })
        .map_err(|_| invalid())?;
        if request.len() > FRAME_LIMIT {
            return Err(invalid());
        }
        // SO_PEERCRED captures effective IDs at connect, but Linux's automatic
        // SCM_CREDENTIALS uses real IDs. Native setuid sudo has different IDs;
        // supply the current effective identity explicitly so the kernel checks
        // it against this process and the coordinator can keep its exact match.
        let credentials = socket::UnixCredentials::from(nix::libc::ucred {
            pid: nix::unistd::getpid().as_raw(),
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        });
        let sent = socket::sendmsg::<UnixAddr>(
            self.socket.as_raw_fd(),
            &[std::io::IoSlice::new(&request)],
            &[socket::ControlMessage::ScmCredentials(&credentials)],
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            None,
        )?;
        if sent != request.len() {
            return Err(invalid());
        }
        let packet = self.receive(Instant::now() + Duration::from_secs(3))?;
        let response: Response = serde_json::from_slice(&packet.bytes).map_err(|_| invalid())?;
        if response.schema != SUDO_SCHEMA {
            return Err(invalid());
        }
        // Root peer identity was established before request transmission and is
        // retained by pidfd. Any optional kernel sender credentials must agree.
        if packet
            .credentials
            .is_some_and(|credentials| credentials.uid() != 0)
        {
            return Err(denied());
        }
        Ok((response, packet.descriptors))
    }

    pub fn admit(
        &mut self,
        command_info: Vec<OsString>,
        arguments: Vec<OsString>,
        environment: Vec<OsString>,
    ) -> io::Result<()> {
        if boot_time()? >= self.deadline {
            return Err(denied());
        }
        let (response, mut descriptors) = self.exchange(Request::Admit {
            command_info,
            arguments,
            environment,
        })?;
        if response.decision != Decision::Managed
            || descriptors.len() < 3
            || descriptors.len() > 32
            || u128::from(response.hard_deadline_milliseconds) != self.deadline.as_millis()
            || response.grant.as_deref() != Some(self.grant.as_str())
        {
            return Err(denied());
        }
        let procs = descriptors.remove(0);
        // Self attachment avoids migrating an unretained submitted numeric PID.
        // Attach before every gate/deadline check: either a prior kill is
        // observed through its permanent gate, or a later kill contains us.
        if nix::unistd::write(&procs, b"0")? != 1 {
            return Err(invalid());
        }
        for gate in &descriptors {
            if !quiet(gate)? {
                return Err(denied());
            }
        }
        if !quiet(&self.coordinator)? || boot_time()? >= self.deadline {
            return Err(denied());
        }
        let (response, descriptors) = self.exchange(Request::Attached)?;
        if response.decision != Decision::Attached || !descriptors.is_empty() {
            return Err(denied());
        }
        Ok(())
    }

    pub fn finish(&mut self) {
        // Completion only relinquishes this native invocation, not the grant.
        // Uncertain close never invents success or retries a use charge.
        let _ = self.exchange(Request::Complete);
    }
}

pub(crate) fn field<'a>(values: &'a [OsString], name: &[u8]) -> io::Result<&'a OsStr> {
    let mut found = None;
    for value in values {
        let bytes = value.as_bytes();
        let separator = bytes
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(invalid)?;
        let (key, tail) = bytes.split_at(separator);
        let value = &tail[1..];
        if key == name {
            if found.is_some() {
                return Err(invalid());
            }
            found = Some(OsStr::from_bytes(value));
        }
    }
    found.ok_or_else(invalid)
}

fn managed_routing(runtime: &Path, uid: u32) -> io::Result<bool> {
    match protected(runtime, true) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    let mut names = vec![format!("user-{uid}")];
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    if membership.len() > 8192 {
        return Err(invalid());
    }
    if let Some(path) = membership.lines().find_map(|line| line.strip_prefix("0::")) {
        if let Some(id) = path
            .strip_prefix("/system.slice/dev-auth-workload-")
            .and_then(|tail| tail.strip_suffix(".service"))
        {
            if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(denied());
            }
            let directory = protected(
                &Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')),
                true,
            )?;
            let metadata = directory.metadata()?;
            let identity = (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino());
            names.insert(0, format!("workload-{uid}-{identity:032x}"));
        }
    }
    for name in names {
        match protected(&runtime.join(name), false) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn protected(path: &Path, directory: bool) -> io::Result<File> {
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(denied());
    }
    for ancestor in path.parent().ok_or_else(denied)?.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(denied());
        }
    }
    let file = File::options()
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    use std::os::unix::fs::FileTypeExt;
    if metadata.uid() != 0
        || (!metadata.file_type().is_socket() && metadata.mode() & 0o022 != 0)
        || metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
    {
        return Err(denied());
    }
    Ok(file)
}

fn quiet(fd: &OwnedFd) -> io::Result<bool> {
    let mut descriptors = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    Ok(poll(&mut descriptors, PollTimeout::ZERO)? == 0)
}

fn boot_time() -> io::Result<Duration> {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)?;
    Ok(Duration::new(
        u64::try_from(time.tv_sec()).map_err(|_| invalid())?,
        u32::try_from(time.tv_nsec()).map_err(|_| invalid())?,
    ))
}
pub(crate) fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange_credentials(pass_credentials_before_send: bool) -> socket::UnixCredentials {
        let (sender, receiver) = socket::socketpair(
            socket::AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .unwrap();
        if pass_credentials_before_send {
            socket::setsockopt(&receiver, socket::sockopt::PassCred, &true).unwrap();
        }
        let coordinator = socket::getsockopt(&sender, socket::sockopt::PeerPidfd).unwrap();
        let mut client = Client {
            socket: sender,
            coordinator,
            deadline: Duration::ZERO,
            grant: String::new(),
        };
        let server = std::thread::spawn(move || {
            let mut ready = [PollFd::new(receiver.as_fd(), PollFlags::POLLIN)];
            assert_eq!(poll(&mut ready, 3000_u16).unwrap(), 1);
            // With no receive option at send time, only sender-supplied
            // credentials identify this queued frame. Automatic credentials
            // otherwise arrive as an unidentified sender, even for one UID.
            socket::setsockopt(&receiver, socket::sockopt::PassCred, &true).unwrap();
            let packet = receive_owned(&receiver).unwrap();
            let response = serde_json::to_vec(&Response {
                schema: SUDO_SCHEMA.into(),
                decision: Decision::Native,
                hard_deadline_milliseconds: 0,
                grant: None,
            })
            .unwrap();
            socket::send(receiver.as_raw_fd(), &response, MsgFlags::MSG_NOSIGNAL).unwrap();
            packet.credentials.unwrap()
        });
        let result = client.exchange(Request::Preflight {
            uid: nix::unistd::getuid().as_raw(),
        });
        let credentials = server.join().unwrap();
        assert_eq!(result.unwrap().0.decision, Decision::Native);
        credentials
    }

    #[test]
    fn messages_carry_explicit_effective_identity() {
        let credentials = exchange_credentials(false);
        assert_eq!(credentials.pid(), nix::unistd::getpid().as_raw());
        assert_eq!(credentials.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(credentials.gid(), nix::unistd::getegid().as_raw());
    }

    #[test]
    #[ignore = "requires a native root-approved child with differing real/effective UID and GID"]
    fn native_setid_messages_match_effective_peer_identity() {
        assert!(nix::unistd::geteuid().is_root());
        assert_ne!(nix::unistd::getuid(), nix::unistd::geteuid());
        assert_ne!(nix::unistd::getgid(), nix::unistd::getegid());
        let credentials = exchange_credentials(true);
        assert_eq!(credentials.pid(), nix::unistd::getpid().as_raw());
        assert_eq!(credentials.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(credentials.gid(), nix::unistd::getegid().as_raw());
    }

    #[test]
    fn exact_native_fields_reject_duplicate_and_missing_identity() {
        assert_eq!(
            field(&["uid=1000".into(), "user=example".into()], b"uid").unwrap(),
            "1000"
        );
        assert!(field(&["uid=1000".into(), "uid=0".into()], b"uid").is_err());
        assert!(field(&["uid=1000".into()], b"user").is_err());
        assert!(field(&["uid=1000".into(), "malformed".into()], b"uid").is_err());
    }
}
