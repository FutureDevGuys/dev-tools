use crate::broker_protocol::{
    decode_response_frame, encode_request_frame, BrokerRequest, BrokerRequestEnvelope,
    BrokerResponse, BrokerSessionProbe, BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES,
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

pub const SYSTEM_BROKER_SOCKET: &str = "/run/dev-auth/broker.sock";
pub const USER_BROKER_SOCKET_ENV: &str = "DEV_AUTH_USER_BROKER_SOCKET";
pub const USER_BROKER_SESSION_ENV: &str = "DEV_AUTH_USER_SESSION";
#[cfg(target_os = "linux")]
pub const SYSTEM_CONTROL_SOCKET: &str = "/run/dev-auth/control.sock";
const IO_TIMEOUT: Duration = Duration::from_secs(2);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
    let payload = encode_request_frame(request)?;
    let length = u32::try_from(payload.len()).context("broker request frame is too large")?;
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect to workload broker at {}", socket.display()))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .context("set broker read timeout")?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .context("set broker write timeout")?;
    stream
        .write_all(&length.to_be_bytes())
        .context("write broker frame length")?;
    stream.write_all(&payload).context("write broker request")?;
    stream.flush().context("flush broker request")?;

    let mut length_bytes = [0_u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .context("read broker response length")?;
    let response_length = u32::from_be_bytes(length_bytes) as usize;
    if response_length > MAX_BROKER_FRAME_BYTES {
        bail!("broker response exceeds the frame limit");
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .context("read broker response")?;
    decode_response_frame(&response)
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
    let payload = encode_control_request(&ControlEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        request,
    })?;
    let response = exchange_raw_at(socket, &payload, "broker control")?;
    let response = decode_control_response(&response)?;
    if response.request_id != request_id {
        bail!("broker control response correlation does not match the request");
    }
    Ok(response.response)
}

fn exchange_raw_at(socket: &Path, payload: &[u8], description: &str) -> Result<Vec<u8>> {
    if payload.len() > MAX_BROKER_FRAME_BYTES {
        bail!("{description} request exceeds the frame limit");
    }
    let length = u32::try_from(payload.len()).context("broker request frame is too large")?;
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect to {description} at {}", socket.display()))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .with_context(|| format!("set {description} read timeout"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .with_context(|| format!("set {description} write timeout"))?;
    stream
        .write_all(&length.to_be_bytes())
        .with_context(|| format!("write {description} frame length"))?;
    stream
        .write_all(payload)
        .with_context(|| format!("write {description} request"))?;
    stream
        .flush()
        .with_context(|| format!("flush {description} request"))?;

    let mut length_bytes = [0_u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .with_context(|| format!("read {description} response length"))?;
    let response_length = u32::from_be_bytes(length_bytes) as usize;
    if response_length > MAX_BROKER_FRAME_BYTES {
        bail!("{description} response exceeds the frame limit");
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .with_context(|| format!("read {description} response"))?;
    Ok(response)
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
    use std::os::unix::net::UnixListener;
    use std::thread;

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
}
