use crate::packet::{receive_owned, Packet, FRAME_LIMIT};
use crate::sudo_wire::{Decision, Message, Request, Response, SUDO_HELLO, SUDO_SCHEMA};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{self, MsgFlags, SockFlag, SockType, UnixAddr};
use std::ffi::{CStr, OsStr, OsString};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Unreachable,
    Unanswered,
    Denied,
    /// The coordinator drains and admits no new sudo (ADR 0141).
    Draining,
}

impl Refusal {
    pub(crate) fn message(self) -> &'static CStr {
        match self {
            Self::Unreachable => c"dev-auth: managed sudo routing is selected, but the grant coordinator is unreachable; start dev-auth-grants.service to restore native sudo\n",
            Self::Unanswered => c"dev-auth: the grant coordinator did not answer; retry, or restart dev-auth-grants.service to end every grant and restore native sudo\n",
            Self::Denied => c"dev-auth: managed sudo admission denied; see `dev-auth privilege grant status`, or run `dev-auth privilege leave` to restore native sudo\n",
            Self::Draining => c"dev-auth: the grant coordinator is draining and admits no new sudo; running commands continue; rerun this step once it restarts\n",
        }
    }
}

impl From<io::Error> for Refusal {
    fn from(_: io::Error) -> Self {
        Self::Denied
    }
}

impl From<nix::errno::Errno> for Refusal {
    fn from(_: nix::errno::Errno) -> Self {
        Self::Denied
    }
}

pub(crate) fn initialize(user_info: &[OsString], options: &[OsString]) -> Result<State, Refusal> {
    let uid = field(user_info, b"uid")?
        .to_str()
        .ok_or_else(invalid)?
        .parse::<u32>()
        .map_err(|_| invalid())?;
    let user = field(user_info, b"user")?.as_bytes().to_vec();
    if user.is_empty() || user.len() > 256 || !nix::unistd::Uid::effective().is_root() {
        return Err(Refusal::Denied);
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
            return Err(Refusal::Denied);
        }
        let value = PathBuf::from(OsStr::from_bytes(&tail[1..]));
        match key {
            b"runtime" => runtime = value,
            b"frontend" => frontend = value,
            _ => return Err(Refusal::Denied),
        }
    }
    if !runtime.is_absolute() || !frontend.is_absolute() {
        return Err(Refusal::Denied);
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            coordinator_unreachable(routing, error.kind())?;
            return Ok(state);
        }
        Err(error) => return Err(error.into()),
    }
    let socket = socket::socket(
        socket::AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    if let Err(error) = socket::connect(socket.as_raw_fd(), &UnixAddr::new(&path)?) {
        coordinator_unreachable(routing, io::Error::from(error).kind())?;
        return Ok(state);
    }
    let peer = socket::getsockopt(&socket, socket::sockopt::PeerCredentials)?;
    let coordinator = socket::getsockopt(&socket, socket::sockopt::PeerPidfd)?;
    if peer.uid() != 0 {
        return Err(Refusal::Denied);
    }
    let mut client = Client {
        socket,
        coordinator,
        deadline: Duration::ZERO,
        grant: String::new(),
    };
    let owned = |client: &Client| Ok(routing || managed_job(peer.pid(), &client.coordinator)?);
    let Some(response) = consult(&mut client, uid, owned)? else {
        return Ok(state);
    };
    match route(response.decision)? {
        Route::Native => return Ok(state),
        Route::Managed => {}
        Route::Relay => state.relay = true,
    }
    client.deadline = Duration::from_millis(response.hard_deadline_milliseconds);
    client.grant = response.grant.ok_or_else(invalid)?;
    if client.grant.len() != 32
        || !client
            .grant
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::Denied);
    }
    if boot_time()? >= client.deadline {
        return Err(Refusal::Denied);
    }
    state.client = Some(client);
    Ok(state)
}

/// How this invocation proceeds when no coordinator accepts its connection.
/// An installed but unavailable service cannot revoke ordinary native
/// behavior for an unselected account. Selected routing always denies.
fn coordinator_unreachable(routing: bool, error: io::ErrorKind) -> Result<(), Refusal> {
    if routing {
        Err(Refusal::Unreachable)
    } else if matches!(
        error,
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    ) {
        Ok(())
    } else {
        Err(Refusal::Denied)
    }
}

/// The coordinator's preflight answer, or `None` when this invocation has
/// native sudo because the coordinator never answered and `owned` finds that
/// the coordinator owns nothing here, as when no coordinator runs. Ownership
/// that cannot be read denies (ADR 0138).
fn consult(
    client: &mut Client,
    uid: u32,
    owned: impl FnOnce(&Client) -> io::Result<bool>,
) -> Result<Option<Response>, Refusal> {
    match preflight(client, uid) {
        Err(Refusal::Unanswered) if !owned(client).unwrap_or(true) => Ok(None),
        answer => answer.map(Some),
    }
}

/// Whether this process runs beneath the coordinator's own cgroup, where
/// every process belongs to one of its managed jobs and routes through that
/// job's grant without a routing marker.
fn managed_job(coordinator: i32, identity: &OwnedFd) -> io::Result<bool> {
    if coordinator <= 0 {
        return Err(denied());
    }
    let own = unified_cgroup(Path::new("/proc/self/cgroup"))?;
    let theirs = unified_cgroup(Path::new(&format!("/proc/{coordinator}/cgroup")))?;
    if !quiet(identity)? {
        return Err(denied());
    }
    match (own, theirs) {
        (Some(own), Some(theirs)) => Ok(beneath(&own, &theirs)),
        _ => Err(invalid()),
    }
}

fn beneath(cgroup: &str, ancestor: &str) -> bool {
    cgroup
        .strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn unified_cgroup(record: &Path) -> io::Result<Option<String>> {
    let membership = std::fs::read_to_string(record)?;
    if membership.len() > 8192 {
        return Err(invalid());
    }
    Ok(membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned))
}

fn preflight(client: &mut Client, uid: u32) -> Result<Response, Refusal> {
    let hello = client
        .receive(Instant::now() + Duration::from_secs(3))
        .map_err(|_| Refusal::Unanswered)?;
    if hello.bytes != SUDO_HELLO || !hello.descriptors.is_empty() {
        return Err(Refusal::Unanswered);
    }
    let (response, descriptors) = client
        .exchange(Request::Preflight { uid })
        .map_err(|_| Refusal::Unanswered)?;
    if !descriptors.is_empty() {
        return Err(Refusal::Unanswered);
    }
    Ok(response)
}

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Native,
    Managed,
    Relay,
}

/// How this invocation proceeds after the coordinator's preflight answer. The
/// authenticated coordinator owns routing: its native answer means no grant is
/// selected, including when it withdrew a marker this invocation saw above.
fn route(decision: Decision) -> Result<Route, Refusal> {
    match decision {
        Decision::Native => Ok(Route::Native),
        Decision::Managed => Ok(Route::Managed),
        Decision::Relay => Ok(Route::Relay),
        Decision::Draining => Err(Refusal::Draining),
        _ => Err(Refusal::Denied),
    }
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
    if let Some(path) = unified_cgroup(Path::new("/proc/self/cgroup"))? {
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

    // A routing marker read before the coordinator withdrew it must not deny
    // the invocation once the coordinator answers that no grant is selected.
    #[test]
    fn coordinator_reported_native_routing_is_honored_after_a_marker_was_seen() {
        assert_eq!(route(Decision::Native).unwrap(), Route::Native);
        assert_eq!(route(Decision::Managed).unwrap(), Route::Managed);
        assert_eq!(route(Decision::Relay).unwrap(), Route::Relay);
        for denial in [Decision::Denied, Decision::Unavailable, Decision::Attached] {
            assert_eq!(route(denial), Err(Refusal::Denied));
        }
    }

    #[test]
    fn a_draining_coordinator_tells_the_user_to_rerun_the_step() {
        assert_eq!(route(Decision::Draining), Err(Refusal::Draining));
    }

    #[test]
    fn selected_routing_reports_an_unreachable_coordinator() {
        for absent in [io::ErrorKind::NotFound, io::ErrorKind::ConnectionRefused] {
            assert_eq!(
                coordinator_unreachable(true, absent),
                Err(Refusal::Unreachable),
                "{absent:?}"
            );
            assert_eq!(coordinator_unreachable(false, absent), Ok(()), "{absent:?}");
        }
        assert_eq!(
            coordinator_unreachable(true, io::ErrorKind::PermissionDenied),
            Err(Refusal::Unreachable)
        );
        assert_eq!(
            coordinator_unreachable(false, io::ErrorKind::PermissionDenied),
            Err(Refusal::Denied)
        );
    }

    fn fake_coordinator(serve: impl FnOnce(OwnedFd) + Send + 'static) -> Option<Response> {
        let (client, coordinator) = socket::socketpair(
            socket::AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .unwrap();
        let identity = socket::getsockopt(&client, socket::sockopt::PeerPidfd).unwrap();
        let server = std::thread::spawn(move || serve(coordinator));
        let mut client = Client {
            socket: client,
            coordinator: identity,
            deadline: Duration::ZERO,
            grant: String::new(),
        };
        let answer = preflight(&mut client, 1000);
        server.join().unwrap();
        match answer {
            Ok(response) => Some(response),
            Err(refusal) => {
                assert_eq!(refusal, Refusal::Unanswered);
                None
            }
        }
    }

    fn wait_readable(fd: &OwnedFd) {
        let mut ready = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut ready, 3000_u16).unwrap(), 1);
    }

    #[test]
    fn a_coordinator_that_closes_before_answering_has_not_answered() {
        assert!(
            fake_coordinator(drop).is_none(),
            "closed before its greeting"
        );
        assert!(
            fake_coordinator(|coordinator| {
                socket::send(coordinator.as_raw_fd(), SUDO_HELLO, MsgFlags::MSG_NOSIGNAL).unwrap();
                wait_readable(&coordinator);
            })
            .is_none(),
            "closed after reading the preflight request"
        );
        let answered = fake_coordinator(|coordinator| {
            socket::send(coordinator.as_raw_fd(), SUDO_HELLO, MsgFlags::MSG_NOSIGNAL).unwrap();
            wait_readable(&coordinator);
            receive_owned(&coordinator).unwrap();
            let response = serde_json::to_vec(&Response {
                schema: SUDO_SCHEMA.into(),
                decision: Decision::Native,
                hard_deadline_milliseconds: 0,
                grant: None,
            })
            .unwrap();
            socket::send(coordinator.as_raw_fd(), &response, MsgFlags::MSG_NOSIGNAL).unwrap();
        });
        assert_eq!(answered.unwrap().decision, Decision::Native);
    }

    fn consult_fake(
        serve: impl FnOnce(OwnedFd) + Send + 'static,
        owned: io::Result<bool>,
    ) -> Result<Option<Response>, Refusal> {
        let (client, coordinator) = socket::socketpair(
            socket::AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .unwrap();
        let identity = socket::getsockopt(&client, socket::sockopt::PeerPidfd).unwrap();
        let server = std::thread::spawn(move || serve(coordinator));
        let mut client = Client {
            socket: client,
            coordinator: identity,
            deadline: Duration::ZERO,
            grant: String::new(),
        };
        let consulted = consult(&mut client, 1000, |_| owned);
        server.join().unwrap();
        consulted
    }

    fn answer_native(coordinator: OwnedFd) {
        socket::send(coordinator.as_raw_fd(), SUDO_HELLO, MsgFlags::MSG_NOSIGNAL).unwrap();
        wait_readable(&coordinator);
        receive_owned(&coordinator).unwrap();
        let response = serde_json::to_vec(&Response {
            schema: SUDO_SCHEMA.into(),
            decision: Decision::Native,
            hard_deadline_milliseconds: 0,
            grant: None,
        })
        .unwrap();
        socket::send(coordinator.as_raw_fd(), &response, MsgFlags::MSG_NOSIGNAL).unwrap();
    }

    #[test]
    fn an_unanswered_invocation_has_native_sudo_unless_the_coordinator_owns_it() {
        assert!(
            matches!(consult_fake(drop, Ok(false)), Ok(None)),
            "an account the coordinator does not own has native sudo"
        );
        assert_eq!(
            consult_fake(drop, Ok(true)).err(),
            Some(Refusal::Unanswered),
            "a selected account keeps denying with its reason"
        );
        assert_eq!(
            consult_fake(drop, Err(io::ErrorKind::Interrupted.into())).err(),
            Some(Refusal::Unanswered),
            "ownership that cannot be read denies"
        );
        assert_eq!(
            consult_fake(answer_native, Ok(true))
                .unwrap()
                .map(|response| response.decision),
            Some(Decision::Native),
            "an answering coordinator decides"
        );
    }

    #[test]
    fn only_a_cgroup_beneath_the_coordinators_runs_its_jobs() {
        let unit = "/system.slice/example.service";
        assert!(beneath(
            &format!("{unit}/grant-{0:032x}/exec-{0:032x}", 1),
            unit
        ));
        assert!(
            !beneath(unit, unit),
            "the coordinator's own cgroup runs no job"
        );
        assert!(!beneath("/system.slice/example.service-sibling/job", unit));
        assert!(!beneath(
            "/user.slice/user-1000.slice/session-1.scope",
            unit
        ));
    }

    #[test]
    fn every_refusal_is_one_short_line_with_a_remedy() {
        for (refusal, remedy) in [
            (Refusal::Unreachable, "start dev-auth-grants.service"),
            (Refusal::Unanswered, "restart dev-auth-grants.service"),
            (Refusal::Denied, "dev-auth privilege leave"),
            (Refusal::Draining, "rerun this step"),
        ] {
            let text = refusal.message().to_str().unwrap();
            assert!(text.starts_with("dev-auth: "), "{text}");
            assert!(text.contains(remedy), "{text}");
            assert!(
                text.ends_with('\n') && text.matches('\n').count() == 1,
                "{text}"
            );
            assert!(text.len() <= 160, "{} bytes: {text}", text.len());
        }
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
