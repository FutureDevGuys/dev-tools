use crate::broker_protocol::{
    decode_response_frame, encode_request_frame, BrokerRequest, BrokerRequestEnvelope,
    BrokerResponse, BrokerSessionProbe, BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES,
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

pub const SYSTEM_BROKER_SOCKET: &str = "/run/dev-auth/broker.sock";
pub const USER_BROKER_SOCKET_ENV: &str = "DEV_AUTH_USER_BROKER_SOCKET";
pub const USER_BROKER_SESSION_ENV: &str = "DEV_AUTH_USER_SESSION";
#[cfg(target_os = "linux")]
pub const SYSTEM_CONTROL_SOCKET: &str = "/run/dev-auth/control.sock";
const LOCAL_IO_TIMEOUT: Duration = Duration::from_secs(2);
// Capability and teardown responses each reserve one absolute 120-second server
// operation budget plus a small framing margin. A teardown's budget is shared
// across cancellation, drain, and cleanup rather than renewed between phases.
const OPERATION_RESPONSE_TIMEOUT: Duration = Duration::from_secs(125);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct BrokerTimeouts {
    local_io: Duration,
    operation_response: Duration,
}

const BROKER_TIMEOUTS: BrokerTimeouts = BrokerTimeouts {
    local_io: LOCAL_IO_TIMEOUT,
    operation_response: OPERATION_RESPONSE_TIMEOUT,
};

impl BrokerTimeouts {
    fn response_timeout(self, request: &BrokerRequest) -> Duration {
        match request {
            BrokerRequest::Probe
            | BrokerRequest::ActivateSession { .. }
            | BrokerRequest::RenewSession { .. } => self.local_io,
            BrokerRequest::EndSession { .. }
            | BrokerRequest::GitCredential { .. }
            | BrokerRequest::InvalidateGitCredential { .. }
            | BrokerRequest::GhExecutionToken
            | BrokerRequest::SignSsh { .. }
            | BrokerRequest::SignReleaseManifest { .. } => self.operation_response,
        }
    }

    #[cfg(target_os = "linux")]
    fn control_response_timeout(
        self,
        request: &crate::control_protocol::ControlRequest,
    ) -> Duration {
        match request {
            crate::control_protocol::ControlRequest::Prepare { .. }
            | crate::control_protocol::ControlRequest::Register { .. }
            | crate::control_protocol::ControlRequest::Renew { .. } => self.local_io,
            crate::control_protocol::ControlRequest::Revoke { .. } => self.operation_response,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveBrokerEndpoint {
    System,
    User(PathBuf),
}

pub fn active_claim_and_probe() -> Result<(
    crate::broker_protocol::LocalSessionClaim,
    BrokerSessionProbe,
)> {
    let strong_claim = crate::linux_admission::local_session_claim()?;
    let user = user_broker_from_environment()?;
    match (strong_claim, user) {
        (crate::broker_protocol::LocalSessionClaim::Present { .. }, Some(_)) => {
            bail!("strong and user-only broker hints are ambiguous")
        }
        (claim @ crate::broker_protocol::LocalSessionClaim::Present { .. }, None) => {
            Ok((claim, probe_system_broker()))
        }
        (crate::broker_protocol::LocalSessionClaim::Absent, Some((session_id, socket))) => Ok((
            crate::broker_protocol::LocalSessionClaim::Present {
                marker: format!("user:{session_id}"),
            },
            probe_at(&socket).unwrap_or_else(|error| BrokerSessionProbe::Unavailable {
                reason: format!("user workload broker probe failed: {error:#}"),
            }),
        )),
        (crate::broker_protocol::LocalSessionClaim::Absent, None) => Ok((
            crate::broker_protocol::LocalSessionClaim::Absent,
            BrokerSessionProbe::NoSession,
        )),
    }
}

pub fn request_active(request: BrokerRequest) -> Result<BrokerResponse> {
    match active_endpoint()? {
        ActiveBrokerEndpoint::System => request_system(request),
        ActiveBrokerEndpoint::User(socket) => request_at(&socket, request),
    }
}

fn active_endpoint() -> Result<ActiveBrokerEndpoint> {
    let strong_claim = crate::linux_admission::local_session_claim()?;
    let user = user_broker_from_environment()?;
    match (strong_claim, user) {
        (crate::broker_protocol::LocalSessionClaim::Present { .. }, Some(_)) => {
            bail!("strong and user-only broker hints are ambiguous")
        }
        (crate::broker_protocol::LocalSessionClaim::Present { .. }, None) => {
            Ok(ActiveBrokerEndpoint::System)
        }
        (crate::broker_protocol::LocalSessionClaim::Absent, Some((_, socket))) => {
            Ok(ActiveBrokerEndpoint::User(socket))
        }
        (crate::broker_protocol::LocalSessionClaim::Absent, None) => {
            bail!("caller is outside an active workload broker session")
        }
    }
}

fn user_broker_from_environment() -> Result<Option<(String, PathBuf)>> {
    let socket = std::env::var_os(USER_BROKER_SOCKET_ENV);
    let session = std::env::var_os(USER_BROKER_SESSION_ENV);
    let (socket, session) = match (socket, session) {
        (Some(socket), Some(session)) => (socket, session),
        (None, None) => return Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            bail!("user workload broker environment is incomplete")
        }
    };
    let session = session
        .into_string()
        .map_err(|_| anyhow::anyhow!("user workload broker session is not UTF-8"))?;
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    let runtime_root = PathBuf::from(format!("/run/user/{owner_uid}/dev-auth-v3"));
    let socket =
        validate_user_broker_hint_at(&runtime_root, Path::new(&socket), &session, owner_uid)?;
    Ok(Some((session, socket)))
}

fn validate_user_broker_hint_at(
    runtime_root: &Path,
    socket: &Path,
    session_id: &str,
    owner_uid: u32,
) -> Result<PathBuf> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("user broker session hint is invalid");
    }
    let sessions = runtime_root.join("user-sessions");
    let session = sessions.join(session_id);
    let expected = session.join("broker.sock");
    if !runtime_root.is_absolute() || socket != expected {
        bail!("user broker socket hint is outside the private runtime");
    }
    for directory in [runtime_root, sessions.as_path(), session.as_path()] {
        let metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("inspect user broker directory {}", directory.display()))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o077 != 0
        {
            bail!("user broker directory has unsafe authority");
        }
    }
    let metadata = fs::symlink_metadata(socket).context("inspect user broker socket")?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("user broker socket has unsafe authority");
    }
    Ok(expected)
}

pub fn probe_system_broker() -> BrokerSessionProbe {
    match probe_at(Path::new(SYSTEM_BROKER_SOCKET)) {
        Ok(probe) => probe,
        Err(error) => BrokerSessionProbe::Unavailable {
            reason: format!("workload broker probe failed: {error:#}"),
        },
    }
}

pub fn probe_at(socket: &Path) -> Result<BrokerSessionProbe> {
    let response = request_at(socket, BrokerRequest::Probe)?;
    match response {
        BrokerResponse::NoSession => Ok(BrokerSessionProbe::NoSession),
        BrokerResponse::Ready {
            session_id,
            owner_uid,
            execution_uid,
            workload,
            profile,
            ..
        } => Ok(BrokerSessionProbe::Verified {
            session_id,
            owner_uid,
            execution_uid,
            workload,
            profile,
        }),
        BrokerResponse::Denied { code, message } => Ok(BrokerSessionProbe::Invalid {
            reason: format!("{code}: {message}"),
        }),
        BrokerResponse::Accepted
        | BrokerResponse::GitCredential { .. }
        | BrokerResponse::GhExecutionToken { .. }
        | BrokerResponse::Signature { .. } => {
            bail!("broker returned an operation response to a session probe")
        }
    }
}

pub fn request_system(request: BrokerRequest) -> Result<crate::broker_protocol::BrokerResponse> {
    request_at(Path::new(SYSTEM_BROKER_SOCKET), request)
}

pub fn request_at(
    socket: &Path,
    request: BrokerRequest,
) -> Result<crate::broker_protocol::BrokerResponse> {
    let request_id = request_id();
    let envelope = BrokerRequestEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        request,
    };
    let response = exchange_at(socket, &envelope)?;
    if response.request_id != request_id {
        bail!("broker response correlation does not match the request");
    }
    Ok(response.response)
}

pub fn exchange_at(
    socket: &Path,
    request: &BrokerRequestEnvelope,
) -> Result<crate::broker_protocol::BrokerResponseEnvelope> {
    exchange_at_with_timeouts(socket, request, BROKER_TIMEOUTS)
}

fn exchange_at_with_timeouts(
    socket: &Path,
    request: &BrokerRequestEnvelope,
    timeouts: BrokerTimeouts,
) -> Result<crate::broker_protocol::BrokerResponseEnvelope> {
    let payload = encode_request_frame(request)?;
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect to workload broker at {}", socket.display()))?;
    write_frame_with_clock(
        &mut stream,
        &payload,
        timeouts.local_io,
        "broker",
        Instant::now,
    )?;
    let response = read_frame_with_clock(
        &mut stream,
        timeouts.response_timeout(&request.request),
        "broker",
        Instant::now,
    )?;
    decode_response_frame(&response)
}

trait FramedIo: Read + Write {
    fn set_frame_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_frame_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl FramedIo for UnixStream {
    fn set_frame_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }

    fn set_frame_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

#[derive(Clone, Copy)]
struct AbsoluteDeadline {
    started_at: Instant,
    budget: Duration,
}

impl AbsoluteDeadline {
    fn new(started_at: Instant, budget: Duration) -> Self {
        Self { started_at, budget }
    }

    fn remaining(self, now: Instant) -> io::Result<Duration> {
        self.budget
            .checked_sub(now.saturating_duration_since(self.started_at))
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame deadline elapsed"))
    }
}

fn write_frame_with_clock<S, C>(
    stream: &mut S,
    payload: &[u8],
    timeout: Duration,
    description: &str,
    mut now: C,
) -> Result<()>
where
    S: FramedIo,
    C: FnMut() -> Instant,
{
    let length = u32::try_from(payload.len()).context("broker request frame is too large")?;
    let deadline = AbsoluteDeadline::new(now(), timeout);
    write_all_before_deadline(stream, &length.to_be_bytes(), deadline, &mut now)
        .with_context(|| format!("write {description} frame length"))?;
    write_all_before_deadline(stream, payload, deadline, &mut now)
        .with_context(|| format!("write {description} request"))?;
    flush_before_deadline(stream, deadline, &mut now)
        .with_context(|| format!("flush {description} request"))
}

fn read_frame_with_clock<S, C>(
    stream: &mut S,
    timeout: Duration,
    description: &str,
    mut now: C,
) -> Result<Vec<u8>>
where
    S: FramedIo,
    C: FnMut() -> Instant,
{
    let deadline = AbsoluteDeadline::new(now(), timeout);
    let mut length_bytes = [0_u8; 4];
    read_exact_before_deadline(stream, &mut length_bytes, deadline, &mut now)
        .with_context(|| format!("read {description} response length"))?;
    let response_length = u32::from_be_bytes(length_bytes) as usize;
    if response_length > MAX_BROKER_FRAME_BYTES {
        bail!("{description} response exceeds the frame limit");
    }
    let mut response = vec![0_u8; response_length];
    read_exact_before_deadline(stream, &mut response, deadline, &mut now)
        .with_context(|| format!("read {description} response"))?;
    Ok(response)
}

fn write_all_before_deadline<S, C>(
    stream: &mut S,
    mut buffer: &[u8],
    deadline: AbsoluteDeadline,
    now: &mut C,
) -> io::Result<()>
where
    S: FramedIo,
    C: FnMut() -> Instant,
{
    while !buffer.is_empty() {
        stream.set_frame_write_timeout(Some(deadline.remaining(now())?))?;
        match stream.write(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write the complete frame",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn flush_before_deadline<S, C>(
    stream: &mut S,
    deadline: AbsoluteDeadline,
    now: &mut C,
) -> io::Result<()>
where
    S: FramedIo,
    C: FnMut() -> Instant,
{
    stream.set_frame_write_timeout(Some(deadline.remaining(now())?))?;
    stream.flush()
}

fn read_exact_before_deadline<S, C>(
    stream: &mut S,
    mut buffer: &mut [u8],
    deadline: AbsoluteDeadline,
    now: &mut C,
) -> io::Result<()>
where
    S: FramedIo,
    C: FnMut() -> Instant,
{
    while !buffer.is_empty() {
        stream.set_frame_read_timeout(Some(deadline.remaining(now())?))?;
        match stream.read(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "frame ended before its declared length",
                ));
            }
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn control_request_system(
    request: crate::control_protocol::ControlRequest,
) -> Result<crate::control_protocol::ControlResponse> {
    control_request_at(Path::new(SYSTEM_CONTROL_SOCKET), request)
}

#[cfg(target_os = "linux")]
pub fn control_request_at(
    socket: &Path,
    request: crate::control_protocol::ControlRequest,
) -> Result<crate::control_protocol::ControlResponse> {
    use crate::control_protocol::{
        decode_control_response, encode_control_request, ControlEnvelope,
    };
    let request_id = request_id();
    let envelope = ControlEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        request,
    };
    let payload = encode_control_request(&envelope)?;
    let response = exchange_raw_at(
        socket,
        &payload,
        "broker control",
        &envelope.request,
        BROKER_TIMEOUTS,
    )?;
    let response = decode_control_response(&response)?;
    if response.request_id != request_id {
        bail!("broker control response correlation does not match the request");
    }
    Ok(response.response)
}

#[cfg(target_os = "linux")]
fn exchange_raw_at(
    socket: &Path,
    payload: &[u8],
    description: &str,
    control_request: &crate::control_protocol::ControlRequest,
    timeouts: BrokerTimeouts,
) -> Result<Vec<u8>> {
    if payload.len() > MAX_BROKER_FRAME_BYTES {
        bail!("{description} request exceeds the frame limit");
    }
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect to {description} at {}", socket.display()))?;
    write_frame_with_clock(
        &mut stream,
        payload,
        timeouts.local_io,
        description,
        Instant::now,
    )?;
    read_frame_with_clock(
        &mut stream,
        timeouts.control_response_timeout(control_request),
        description,
        Instant::now,
    )
}

fn request_id() -> String {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest[..32].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_protocol::{encode_response_frame, BrokerResponseEnvelope};
    use std::cell::{Cell, RefCell};
    use std::os::unix::net::UnixListener;
    use std::rc::Rc;
    use std::thread;

    struct StepIo {
        elapsed: Rc<Cell<Duration>>,
        step: Duration,
        read_data: Vec<u8>,
        read_offset: usize,
        written: Vec<u8>,
        read_timeouts: RefCell<Vec<Duration>>,
        write_timeouts: RefCell<Vec<Duration>>,
        flush_count: usize,
    }

    impl StepIo {
        fn new(elapsed: Rc<Cell<Duration>>, step: Duration, read_data: Vec<u8>) -> Self {
            Self {
                elapsed,
                step,
                read_data,
                read_offset: 0,
                written: Vec::new(),
                read_timeouts: RefCell::new(Vec::new()),
                write_timeouts: RefCell::new(Vec::new()),
                flush_count: 0,
            }
        }

        fn advance(&self) {
            self.elapsed.set(self.elapsed.get() + self.step);
        }
    }

    impl Read for StepIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            let Some(byte) = self.read_data.get(self.read_offset).copied() else {
                return Ok(0);
            };
            buffer[0] = byte;
            self.read_offset += 1;
            self.advance();
            Ok(1)
        }
    }

    impl Write for StepIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let Some(byte) = buffer.first().copied() else {
                return Ok(0);
            };
            self.written.push(byte);
            self.advance();
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_count += 1;
            self.advance();
            Ok(())
        }
    }

    impl FramedIo for StepIo {
        fn set_frame_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.read_timeouts
                .borrow_mut()
                .push(timeout.expect("read deadline must be bounded"));
            Ok(())
        }

        fn set_frame_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.write_timeouts
                .borrow_mut()
                .push(timeout.expect("write deadline must be bounded"));
            Ok(())
        }
    }

    #[test]
    fn user_only_broker_hint_requires_the_private_native_runtime_shape() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let session_id = "0123456789abcdef0123456789abcdef";
        let session = root.path().join("user-sessions").join(session_id);
        std::fs::create_dir_all(&session).unwrap();
        std::fs::set_permissions(
            root.path().join("user-sessions"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = session.join("broker.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner_uid =
            std::os::unix::fs::MetadataExt::uid(&std::fs::symlink_metadata(root.path()).unwrap());

        assert_eq!(
            validate_user_broker_hint_at(root.path(), &socket, session_id, owner_uid).unwrap(),
            socket
        );
        assert!(validate_user_broker_hint_at(
            root.path(),
            &socket,
            "ffffffffffffffffffffffffffffffff",
            owner_uid
        )
        .is_err());
    }

    #[test]
    fn probe_uses_bounded_correlated_framing() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).unwrap();
            let request = crate::broker_protocol::decode_request_frame(&request).unwrap();
            let response = BrokerResponseEnvelope {
                version: BROKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                response: BrokerResponse::NoSession,
            };
            let response = encode_response_frame(&response).unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        assert_eq!(probe_at(&socket).unwrap(), BrokerSessionProbe::NoSession);
        server.join().unwrap();
    }

    #[test]
    fn slow_drip_response_cannot_renew_the_frame_deadline() {
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let mut frame = (4_u32).to_be_bytes().to_vec();
        frame.extend_from_slice(b"body");
        let mut stream = StepIo::new(elapsed.clone(), Duration::from_millis(1), frame);
        let started_at = Instant::now();

        let error = read_frame_with_clock(&mut stream, Duration::from_millis(5), "test", || {
            started_at + elapsed.get()
        })
        .unwrap_err();

        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .expect("deadline error")
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(stream.read_offset, 5);
        assert_eq!(
            *stream.read_timeouts.borrow(),
            [5_u64, 4, 3, 2, 1].map(Duration::from_millis)
        );
    }

    #[test]
    fn framed_write_recomputes_one_deadline_across_header_body_and_flush() {
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let mut stream = StepIo::new(elapsed.clone(), Duration::from_millis(1), Vec::new());
        let started_at = Instant::now();

        write_frame_with_clock(&mut stream, b"ok", Duration::from_millis(8), "test", || {
            started_at + elapsed.get()
        })
        .unwrap();

        assert_eq!(stream.written, [0, 0, 0, 2, b'o', b'k']);
        assert_eq!(stream.flush_count, 1);
        assert_eq!(
            *stream.write_timeouts.borrow(),
            [8_u64, 7, 6, 5, 4, 3, 2].map(Duration::from_millis)
        );
    }

    #[test]
    fn capability_and_teardown_responses_share_one_bounded_operation_deadline() {
        assert_eq!(
            BROKER_TIMEOUTS.response_timeout(&BrokerRequest::GhExecutionToken),
            OPERATION_RESPONSE_TIMEOUT
        );
        assert_eq!(OPERATION_RESPONSE_TIMEOUT, Duration::from_secs(125));
        assert_eq!(BROKER_TIMEOUTS.local_io, Duration::from_secs(2));
        assert_eq!(
            BROKER_TIMEOUTS.response_timeout(&BrokerRequest::Probe),
            LOCAL_IO_TIMEOUT
        );
        assert_eq!(
            BROKER_TIMEOUTS.response_timeout(&BrokerRequest::EndSession {
                session_id: "0123456789abcdef0123456789abcdef".into(),
            }),
            OPERATION_RESPONSE_TIMEOUT
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn control_revoke_uses_operation_deadline_without_relaxing_renew() {
        use crate::control_protocol::ControlRequest;

        let session_id = "0123456789abcdef0123456789abcdef";

        assert_eq!(
            BROKER_TIMEOUTS.control_response_timeout(&ControlRequest::Revoke {
                session_id: session_id.into(),
            }),
            OPERATION_RESPONSE_TIMEOUT
        );
        assert_eq!(
            BROKER_TIMEOUTS.control_response_timeout(&ControlRequest::Renew {
                session_id: session_id.into(),
                expires_at_unix: 1,
            }),
            LOCAL_IO_TIMEOUT
        );
    }
}
