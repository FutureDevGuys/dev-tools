use crate::broker_backend::{CapabilityBackend, SystemCapabilityBackend};
use crate::broker_protocol::{
    decode_request_frame, encode_response_frame, BrokerRequest, BrokerResponse,
    BrokerResponseEnvelope, SshOperationPurpose, BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES,
};
use crate::control_protocol::{
    decode_control_request, encode_control_response, ControlRequest, ControlResponse,
    ControlResponseEnvelope,
};
use crate::linux_admission::{peer_evidence, LinuxSessionRegistry};
use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockname, getsockopt, sockopt, UnixAddr};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const SYSTEM_CONTROL_SOCKET: &str = "/run/dev-auth/control.sock";
const PUBLIC_WORKERS: usize = 8;
const PUBLIC_QUEUE: usize = 64;

pub fn serve_system_broker(public_socket: &Path, control_socket: &Path) -> Result<()> {
    let public_listener = bind_socket(public_socket, 0o666)?;
    let control_listener = bind_socket(control_socket, 0o600)?;
    serve_broker(
        public_listener,
        control_listener,
        Arc::new(UnavailableCapabilityBackend),
    )
}

pub fn serve_systemd_broker() -> Result<()> {
    let (public_listener, control_listener) = inherited_systemd_listeners()?;
    let backend = Arc::new(SystemCapabilityBackend::load()?);
    serve_broker(public_listener, control_listener, backend)
}

pub(crate) fn serve_user_session_broker(
    listener: UnixListener,
    mut session: crate::linux_admission::VerifiedLinuxSession,
    backend: SystemCapabilityBackend,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 || owner_uid != session.owner_uid {
        bail!("user broker must run as its native non-root workload owner");
    }
    emit_lifecycle_audit("user_session_start", Some(&session.session_id), "accepted");
    while !stop.load(Ordering::Acquire) {
        let (mut stream, _) = listener.accept().context("accept user broker connection")?;
        if stop.load(Ordering::Acquire) {
            break;
        }
        session.expires_at_unix = OffsetDateTime::now_utc().unix_timestamp() + 15 * 60;
        let _ = handle_user_connection(&mut stream, &session, &backend);
    }
    let result = backend.revoke_session(&session.session_id);
    emit_lifecycle_audit(
        "user_session_stop",
        Some(&session.session_id),
        if result.is_ok() { "revoked" } else { "failed" },
    );
    result
}

fn handle_user_connection(
    stream: &mut UnixStream,
    session: &crate::linux_admission::VerifiedLinuxSession,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
    let credentials = getsockopt(stream, sockopt::PeerCredentials)
        .context("read user broker peer credentials")?;
    if credentials.uid() != session.owner_uid || credentials.pid() <= 0 {
        bail!("user broker peer is outside the documented same-user trust boundary");
    }
    let request = decode_request_frame(&read_frame(stream)?)?;
    let response = session_response(session, request.request, None, backend)?;
    write_frame(
        stream,
        &encode_response_frame(&BrokerResponseEnvelope {
            version: BROKER_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        })?,
    )
}

fn serve_broker(
    public_listener: UnixListener,
    control_listener: UnixListener,
    backend: Arc<dyn CapabilityBackend>,
) -> Result<()> {
    let registry = Arc::new(LinuxSessionRegistry::new());
    let control_registry = Arc::clone(&registry);
    let control_backend = Arc::clone(&backend);
    thread::Builder::new()
        .name("dev-auth-control".into())
        .spawn(move || control_accept_loop(control_listener, control_registry, control_backend))
        .context("start broker control listener")?;
    let reaper_registry = Arc::clone(&registry);
    let reaper_backend = Arc::clone(&backend);
    thread::Builder::new()
        .name("dev-auth-session-reaper".into())
        .spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            if let Err(error) = revoke_stale_sessions(&reaper_registry, reaper_backend.as_ref()) {
                emit_lifecycle_audit("session_reap", None, "failed");
                eprintln!("dev-auth: session reaper failed: {error:#}");
            }
        })
        .context("start broker session reaper")?;

    let (sender, receiver) = mpsc::sync_channel::<UnixStream>(PUBLIC_QUEUE);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..PUBLIC_WORKERS {
        let worker_receiver = Arc::clone(&receiver);
        let worker_registry = Arc::clone(&registry);
        let worker_backend = Arc::clone(&backend);
        thread::Builder::new()
            .name(format!("dev-auth-public-{index}"))
            .spawn(move || public_worker(worker_receiver, worker_registry, worker_backend))
            .context("start broker public worker")?;
    }
    for connection in public_listener.incoming() {
        let stream = connection.context("accept broker public connection")?;
        sender
            .send(stream)
            .map_err(|_| anyhow::anyhow!("broker public worker queue closed"))?;
    }
    bail!("broker public listener stopped unexpectedly")
}

struct UnavailableCapabilityBackend;

impl CapabilityBackend for UnavailableCapabilityBackend {
    fn github_token(
        &self,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionGitHubGrant,
        _owner: &str,
        _repository: &str,
    ) -> Result<crate::runtime::BrokerGitHubToken> {
        bail!("capability backend is unavailable")
    }

    fn gh_token(
        &self,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionGitHubGrant,
    ) -> Result<crate::runtime::BrokerGitHubToken> {
        bail!("capability backend is unavailable")
    }

    fn invalidate_github_token(
        &self,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionGitHubGrant,
        _owner: &str,
        _repository: &str,
    ) -> Result<()> {
        bail!("capability backend is unavailable")
    }

    fn sign_ssh(
        &self,
        _session_id: &str,
        _purpose: SshOperationPurpose,
        _grant: &crate::linux_admission::SessionOperationKeyGrant,
        _payload: &[u8],
    ) -> Result<Vec<u8>> {
        bail!("capability backend is unavailable")
    }

    fn sign_release_manifest(
        &self,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionReleaseSigningGrant,
        _payload: &[u8],
    ) -> Result<Vec<u8>> {
        bail!("capability backend is unavailable")
    }

    fn revoke_session(&self, _session_id: &str) -> Result<()> {
        Ok(())
    }
}

fn inherited_systemd_listeners() -> Result<(UnixListener, UnixListener)> {
    let listen_pid: u32 = std::env::var("LISTEN_PID")
        .context("systemd did not provide LISTEN_PID")?
        .parse()
        .context("systemd LISTEN_PID is invalid")?;
    if listen_pid != std::process::id() {
        bail!("systemd socket activation belongs to another process");
    }
    if std::env::var("LISTEN_FDS").as_deref() != Ok("2")
        || std::env::var("LISTEN_FDNAMES").as_deref() != Ok("public:control")
    {
        bail!("system broker requires the exact public and control socket units");
    }
    validate_inherited_listener(
        3,
        Path::new(crate::broker_client::SYSTEM_BROKER_SOCKET),
        0o666,
    )?;
    validate_inherited_listener(4, Path::new(SYSTEM_CONTROL_SOCKET), 0o600)?;
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    // SAFETY: systemd's socket-activation contract gives this process ownership
    // of exactly descriptors 3 and 4. The exact PID/count/names were checked,
    // both descriptors were successfully queried as Unix listeners at the
    // required root-owned filesystem paths, and no safe owner exists in this
    // process. Converting each descriptor once transfers that ownership into
    // `UnixListener`, whose destructor closes it.
    let public = unsafe { UnixListener::from_raw_fd(3) };
    // SAFETY: the same validated socket-activation contract applies to fd 4,
    // which is distinct from fd 3 and converted exactly once.
    let control = unsafe { UnixListener::from_raw_fd(4) };
    Ok((public, control))
}

fn validate_inherited_listener(fd: i32, expected_path: &Path, expected_mode: u32) -> Result<()> {
    let address: UnixAddr = getsockname(fd).context("inspect inherited broker listener")?;
    if address.path() != Some(expected_path) {
        bail!("inherited broker listener has the wrong socket path");
    }
    let metadata = fs::symlink_metadata(expected_path)
        .with_context(|| format!("inspect inherited socket {}", expected_path.display()))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != expected_mode
    {
        bail!("inherited broker listener has unsafe filesystem authority");
    }
    Ok(())
}

fn public_worker(
    receiver: Arc<Mutex<mpsc::Receiver<UnixStream>>>,
    registry: Arc<LinuxSessionRegistry>,
    backend: Arc<dyn CapabilityBackend>,
) {
    loop {
        let stream = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        let Ok(mut stream) = stream else {
            return;
        };
        // Invalid or truncated frames are closed without reflecting parser, path, or
        // kernel details to an untrusted peer. Correlated policy denials are emitted
        let _ = handle_public_connection(&mut stream, &registry, backend.as_ref());
    }
}

fn handle_public_connection(
    stream: &mut UnixStream,
    registry: &LinuxSessionRegistry,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
    revoke_stale_sessions(registry, backend)?;
    let peer = peer_evidence(stream)?;
    let request_bytes = read_frame(stream)?;
    let request = decode_request_frame(&request_bytes)?;
    let audit_request = request.request.clone();
    if let BrokerRequest::ActivateSession { session_id } = &request.request {
        let response = match registry.activate_pending(peer, session_id) {
            Ok(session) => ready_response(&session)?,
            Err(_) => BrokerResponse::Denied {
                code: "session_invalid".into(),
                message: "pending workload admission could not be activated".into(),
            },
        };
        emit_request_audit(None, &audit_request, &response);
        return write_frame(
            stream,
            &encode_response_frame(&BrokerResponseEnvelope {
                version: BROKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                response,
            })?,
        );
    }
    let (response, session_audited) = match registry.probe_peer(&peer) {
        Err(_) => (
            BrokerResponse::Denied {
                code: "session_invalid".into(),
                message: "workload session admission could not be verified".into(),
            },
            false,
        ),
        Ok(None) => (
            match request.request {
                BrokerRequest::Probe => BrokerResponse::NoSession,
                BrokerRequest::ActivateSession { .. }
                | BrokerRequest::RenewSession { .. }
                | BrokerRequest::EndSession { .. }
                | BrokerRequest::GitCredential { .. }
                | BrokerRequest::InvalidateGitCredential { .. }
                | BrokerRequest::GhExecutionToken
                | BrokerRequest::SignSsh { .. }
                | BrokerRequest::SignReleaseManifest { .. } => BrokerResponse::Denied {
                    code: "no_session".into(),
                    message: "caller is outside a registered workload session".into(),
                },
            },
            false,
        ),
        Ok(Some(session)) => (
            session_response(&session, request.request, Some(registry), backend)?,
            true,
        ),
    };
    if !session_audited {
        emit_request_audit(None, &audit_request, &response);
    }
    write_frame(
        stream,
        &encode_response_frame(&BrokerResponseEnvelope {
            version: BROKER_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        })?,
    )
}

fn session_response(
    session: &crate::linux_admission::VerifiedLinuxSession,
    request: BrokerRequest,
    registry: Option<&LinuxSessionRegistry>,
    backend: &dyn CapabilityBackend,
) -> Result<BrokerResponse> {
    let audit_request = request.clone();
    let response = match request {
        BrokerRequest::Probe => ready_response(session)?,
        BrokerRequest::ActivateSession { .. } => BrokerResponse::Denied {
            code: "session_invalid".into(),
            message: "an active workload cannot activate another admission".into(),
        },
        BrokerRequest::RenewSession { session_id } => {
            if session_id != session.session_id || registry.is_none() {
                BrokerResponse::Denied {
                    code: "session_invalid".into(),
                    message: "session renewal does not match the admitted workload".into(),
                }
            } else {
                registry
                    .context("strong session registry is unavailable")?
                    .renew(&session_id, lease_expiry())?;
                BrokerResponse::Accepted
            }
        }
        BrokerRequest::EndSession { session_id } => {
            if session_id != session.session_id || registry.is_none() {
                BrokerResponse::Denied {
                    code: "session_invalid".into(),
                    message: "session teardown does not match the admitted workload".into(),
                }
            } else {
                let existed = registry
                    .context("strong session registry is unavailable")?
                    .revoke(&session_id)?;
                if existed {
                    backend.revoke_session(&session_id)?;
                }
                BrokerResponse::Accepted
            }
        }
        operation if !session_authorizes(session, &operation) => BrokerResponse::Denied {
            code: "resource_denied".into(),
            message: "workload profile does not authorize the requested capability".into(),
        },
        BrokerRequest::GitCredential {
            owner, repository, ..
        } => github_token_response(
            backend,
            session,
            &owner,
            &repository,
            GitHubResponseKind::GitCredential,
        ),
        BrokerRequest::InvalidateGitCredential {
            owner, repository, ..
        } => match session.authority.github.as_ref() {
            Some(grant) => match backend.invalidate_github_token(
                &session.session_id,
                grant,
                &owner,
                &repository,
            ) {
                Ok(()) => BrokerResponse::Accepted,
                Err(_) => provider_denial(),
            },
            None => BrokerResponse::Denied {
                code: "resource_denied".into(),
                message: "workload profile has no GitHub authority".into(),
            },
        },
        BrokerRequest::GhExecutionToken => match session.authority.github.as_ref() {
            Some(grant) => match backend.gh_token(&session.session_id, grant) {
                Ok(token) => token_response(token, GitHubResponseKind::GhExecutionToken),
                Err(_) => provider_denial(),
            },
            None => BrokerResponse::Denied {
                code: "resource_denied".into(),
                message: "workload profile has no GitHub authority".into(),
            },
        },
        BrokerRequest::SignSsh {
            purpose,
            public_key_fingerprint,
            payload,
            ..
        } => match session_operation_key(session, purpose, &public_key_fingerprint) {
            Some(grant) => match backend.sign_ssh(&session.session_id, purpose, grant, &payload) {
                Ok(signature) => BrokerResponse::Signature { signature },
                Err(_) => provider_denial(),
            },
            None => BrokerResponse::Denied {
                code: "resource_denied".into(),
                message: "workload profile has no signing authority".into(),
            },
        },
        BrokerRequest::SignReleaseManifest {
            release_public_key,
            payload,
            ..
        } => match session.authority.release_signing.as_ref() {
            Some(grant) if grant.public_key == release_public_key => {
                match dev_tools_release::validate_unsigned_product_manifest(&payload) {
                    Ok(manifest) if grant.products.contains(&manifest.product) => {
                        match backend.sign_release_manifest(&session.session_id, grant, &payload) {
                            Ok(signature) => BrokerResponse::Signature { signature },
                            Err(_) => provider_denial(),
                        }
                    }
                    Ok(_) | Err(_) => BrokerResponse::Denied {
                        code: "resource_denied".into(),
                        message: "release manifest is outside workload authority".into(),
                    },
                }
            }
            Some(_) | None => BrokerResponse::Denied {
                code: "resource_denied".into(),
                message: "workload profile has no release-signing authority".into(),
            },
        },
    };
    emit_request_audit(Some(session), &audit_request, &response);
    Ok(response)
}

fn ready_response(
    session: &crate::linux_admission::VerifiedLinuxSession,
) -> Result<BrokerResponse> {
    Ok(BrokerResponse::Ready {
        session_id: session.session_id.clone(),
        owner_uid: session.owner_uid,
        execution_uid: session.execution_uid,
        workload: session.workload.clone(),
        profile: session.profile.clone(),
        expires_at: OffsetDateTime::from_unix_timestamp(session.expires_at_unix)?
            .format(&Rfc3339)?,
    })
}

fn lease_expiry() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp() + 15 * 60
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerAuditRecord<'a> {
    schema: &'static str,
    timestamp_unix: i64,
    event: &'static str,
    session_id: Option<&'a str>,
    workload: Option<&'a str>,
    profile: Option<&'a str>,
    capability: &'static str,
    resource_sha256: Option<String>,
    outcome: String,
}

fn emit_request_audit(
    session: Option<&crate::linux_admission::VerifiedLinuxSession>,
    request: &BrokerRequest,
    response: &BrokerResponse,
) {
    let record = request_audit_record(session, request, response);
    if let Ok(line) = serde_json::to_string(&record) {
        eprintln!("{line}");
    }
}

fn request_audit_record<'a>(
    session: Option<&'a crate::linux_admission::VerifiedLinuxSession>,
    request: &BrokerRequest,
    response: &BrokerResponse,
) -> BrokerAuditRecord<'a> {
    let (capability, resource_sha256) = match request {
        BrokerRequest::Probe => ("probe", None),
        BrokerRequest::ActivateSession { .. } => ("session_activate", None),
        BrokerRequest::RenewSession { .. } => ("session_renew", None),
        BrokerRequest::EndSession { .. } => ("session_end", None),
        BrokerRequest::GitCredential {
            protocol,
            host,
            owner,
            repository,
        } => (
            "git_credential",
            Some(public_resource_digest(&[protocol, host, owner, repository])),
        ),
        BrokerRequest::InvalidateGitCredential {
            protocol,
            host,
            owner,
            repository,
        } => (
            "invalidate_git_credential",
            Some(public_resource_digest(&[protocol, host, owner, repository])),
        ),
        BrokerRequest::GhExecutionToken => ("gh_execution_token", None),
        BrokerRequest::SignSsh {
            profile,
            purpose,
            public_key_fingerprint,
            ..
        } => (
            match purpose {
                SshOperationPurpose::GitSigning => "git_signing",
                SshOperationPurpose::Authentication => "ssh_authentication",
            },
            Some(public_resource_digest(&[profile, public_key_fingerprint])),
        ),
        BrokerRequest::SignReleaseManifest {
            profile,
            release_public_key,
            payload,
        } => {
            let product = dev_tools_release::validate_unsigned_product_manifest(payload)
                .map(|manifest| manifest.product)
                .unwrap_or_else(|_| "invalid".into());
            (
                "release_manifest_signing",
                Some(public_resource_digest(&[
                    profile,
                    release_public_key,
                    &product,
                ])),
            )
        }
    };
    let outcome = match response {
        BrokerResponse::Denied { code, .. } => format!("denied:{code}"),
        BrokerResponse::NoSession => "no_session".into(),
        BrokerResponse::Accepted => "accepted".into(),
        BrokerResponse::Ready { .. } => "ready".into(),
        BrokerResponse::GitCredential { .. } => "credential_issued".into(),
        BrokerResponse::GhExecutionToken { .. } => "token_issued".into(),
        BrokerResponse::Signature { .. } => "signature_issued".into(),
    };
    BrokerAuditRecord {
        schema: "dev-auth-broker-audit-v1",
        timestamp_unix: OffsetDateTime::now_utc().unix_timestamp(),
        event: "capability_request",
        session_id: session.map(|session| session.session_id.as_str()),
        workload: session.map(|session| session.workload.as_str()),
        profile: session.map(|session| session.profile.as_str()),
        capability,
        resource_sha256,
        outcome,
    }
}

fn public_resource_digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn emit_lifecycle_audit(event: &'static str, session_id: Option<&str>, outcome: &'static str) {
    #[derive(Serialize)]
    struct LifecycleAuditRecord<'a> {
        schema: &'static str,
        timestamp_unix: i64,
        event: &'static str,
        session_id: Option<&'a str>,
        outcome: &'static str,
    }
    let record = LifecycleAuditRecord {
        schema: "dev-auth-broker-audit-v1",
        timestamp_unix: OffsetDateTime::now_utc().unix_timestamp(),
        event,
        session_id,
        outcome,
    };
    if let Ok(line) = serde_json::to_string(&record) {
        eprintln!("{line}");
    }
}

enum GitHubResponseKind {
    GitCredential,
    GhExecutionToken,
}

fn github_token_response(
    backend: &dyn CapabilityBackend,
    session: &crate::linux_admission::VerifiedLinuxSession,
    owner: &str,
    repository: &str,
    kind: GitHubResponseKind,
) -> BrokerResponse {
    let Some(grant) = &session.authority.github else {
        return BrokerResponse::Denied {
            code: "resource_denied".into(),
            message: "workload profile has no GitHub authority".into(),
        };
    };
    match backend.github_token(&session.session_id, grant, owner, repository) {
        Ok(token) => token_response(token, kind),
        Err(_) => provider_denial(),
    }
}

fn token_response(
    token: crate::runtime::BrokerGitHubToken,
    kind: GitHubResponseKind,
) -> BrokerResponse {
    let Some(expires_at) = OffsetDateTime::from_unix_timestamp(token.expires_at)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
    else {
        return BrokerResponse::Denied {
            code: "provider_unavailable".into(),
            message: "provider returned an invalid token lifetime".into(),
        };
    };
    match kind {
        GitHubResponseKind::GitCredential => BrokerResponse::GitCredential {
            username: "x-access-token".into(),
            password: crate::broker_protocol::SensitiveString::new(token.token.expose().to_owned()),
            expires_at,
        },
        GitHubResponseKind::GhExecutionToken => BrokerResponse::GhExecutionToken {
            token: crate::broker_protocol::SensitiveString::new(token.token.expose().to_owned()),
            expires_at,
        },
    }
}

fn provider_denial() -> BrokerResponse {
    BrokerResponse::Denied {
        code: "provider_unavailable".into(),
        message: "provider denied or could not complete the scoped request".into(),
    }
}

fn session_authorizes(
    session: &crate::linux_admission::VerifiedLinuxSession,
    request: &BrokerRequest,
) -> bool {
    match request {
        BrokerRequest::Probe
        | BrokerRequest::ActivateSession { .. }
        | BrokerRequest::RenewSession { .. }
        | BrokerRequest::EndSession { .. } => true,
        BrokerRequest::GitCredential {
            protocol,
            host,
            owner,
            repository,
        }
        | BrokerRequest::InvalidateGitCredential {
            protocol,
            host,
            owner,
            repository,
        } => {
            protocol == "https"
                && host == "github.com"
                && session
                    .authority
                    .github
                    .as_ref()
                    .is_some_and(|grant| github_grant_contains(grant, owner, repository))
        }
        BrokerRequest::GhExecutionToken => session.authority.github.is_some(),
        BrokerRequest::SignSsh {
            profile,
            purpose,
            public_key_fingerprint,
            ..
        } => {
            profile == &session.profile
                && session_operation_key(session, *purpose, public_key_fingerprint).is_some()
        }
        BrokerRequest::SignReleaseManifest {
            profile,
            release_public_key,
            payload,
        } => {
            profile == &session.profile
                && session
                    .authority
                    .release_signing
                    .as_ref()
                    .is_some_and(|grant| {
                        grant.public_key == *release_public_key
                            && dev_tools_release::validate_unsigned_product_manifest(payload)
                                .is_ok_and(|manifest| grant.products.contains(&manifest.product))
                    })
        }
    }
}

fn session_operation_key<'a>(
    session: &'a crate::linux_admission::VerifiedLinuxSession,
    purpose: SshOperationPurpose,
    fingerprint: &str,
) -> Option<&'a crate::linux_admission::SessionOperationKeyGrant> {
    match purpose {
        SshOperationPurpose::GitSigning => session
            .authority
            .signing
            .as_ref()
            .filter(|key| key.fingerprint == fingerprint),
        SshOperationPurpose::Authentication => session
            .authority
            .ssh
            .iter()
            .find(|key| key.fingerprint == fingerprint),
    }
}

fn github_grant_contains(
    grant: &crate::linux_admission::SessionGitHubGrant,
    owner: &str,
    repository: &str,
) -> bool {
    grant
        .owners
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(owner))
        && (grant.repositories.is_empty()
            || grant
                .repositories
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(repository)))
}

fn control_accept_loop(
    listener: UnixListener,
    registry: Arc<LinuxSessionRegistry>,
    backend: Arc<dyn CapabilityBackend>,
) {
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            return;
        };
        // The control peer is authenticated before parsing. Malformed or
        // unauthenticated input is closed without an oracle over broker internals.
        let _ = handle_control_connection(&mut stream, &registry, backend.as_ref());
    }
}

fn handle_control_connection(
    stream: &mut UnixStream,
    registry: &LinuxSessionRegistry,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
    revoke_stale_sessions(registry, backend)?;
    let credentials = getsockopt(stream, sockopt::PeerCredentials)
        .context("read broker control peer credentials")?;
    let peer_pidfd = getsockopt(stream, sockopt::PeerPidfd)
        .context("read race-free broker control peer pidfd")?;
    if credentials.uid() != 0 {
        bail!("broker control connection is not root-owned");
    }
    let input = read_frame(stream)?;
    let request = decode_control_request(&input)?;
    let (audit_event, audit_session) = match &request.request {
        ControlRequest::Prepare { session } => ("session_prepare", session.session_id.clone()),
        ControlRequest::Register { session } => ("session_register", session.session_id.clone()),
        ControlRequest::Renew { session_id, .. } => ("session_renew", session_id.clone()),
        ControlRequest::Revoke { session_id } => ("session_revoke", session_id.clone()),
    };
    let response = match request.request {
        ControlRequest::Prepare { session } => match registry.prepare_root_owned(*session) {
            Ok(()) => ControlResponse::Accepted,
            Err(_) => ControlResponse::Denied {
                message: "pending session admission was rejected".into(),
            },
        },
        ControlRequest::Register { session } => {
            match registry.register_root_owned(*session, peer_pidfd) {
                Ok(()) => ControlResponse::Accepted,
                Err(_) => ControlResponse::Denied {
                    message: "session registration was rejected".into(),
                },
            }
        }
        ControlRequest::Renew {
            session_id,
            expires_at_unix,
        } => match registry.renew(&session_id, expires_at_unix) {
            Ok(()) => ControlResponse::Accepted,
            Err(_) => ControlResponse::Denied {
                message: "session renewal was rejected".into(),
            },
        },
        ControlRequest::Revoke { session_id } => {
            let existed = registry.revoke(&session_id)?;
            if existed {
                backend.revoke_session(&session_id)?;
            }
            ControlResponse::Revoked { existed }
        }
    };
    let audit_outcome = match &response {
        ControlResponse::Accepted => "accepted",
        ControlResponse::Revoked { existed: true } => "revoked",
        ControlResponse::Revoked { existed: false } => "absent",
        ControlResponse::Denied { .. } => "denied",
    };
    emit_lifecycle_audit(audit_event, Some(&audit_session), audit_outcome);
    let output = encode_control_response(&ControlResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request.request_id,
        response,
    })?;
    write_frame(stream, &output)
}

fn revoke_stale_sessions(
    registry: &LinuxSessionRegistry,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
    for session_id in registry.prune_stale()? {
        backend.revoke_session(&session_id)?;
    }
    Ok(())
}

fn bind_socket(path: &Path, mode: u32) -> Result<UnixListener> {
    let parent = path.parent().context("broker socket path has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect broker socket directory {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!("broker socket directory is not root-owned authority");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == nix::unistd::Uid::effective().as_raw() =>
        {
            fs::remove_file(path).context("remove stale broker socket")?;
        }
        Ok(_) => bail!("broker socket path is occupied by an unowned object"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect broker socket path"),
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind broker socket {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .context("set broker socket permissions")?;
    Ok(listener)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .context("read frame length")?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_BROKER_FRAME_BYTES {
        bail!("broker frame exceeds the size limit");
    }
    let mut input = vec![0_u8; length];
    stream.read_exact(&mut input).context("read broker frame")?;
    Ok(input)
}

fn write_frame(stream: &mut UnixStream, output: &[u8]) -> Result<()> {
    if output.len() > MAX_BROKER_FRAME_BYTES {
        bail!("broker response exceeds the size limit");
    }
    let length = u32::try_from(output.len()).context("broker response length is invalid")?;
    stream
        .write_all(&length.to_be_bytes())
        .context("write broker response length")?;
    stream.write_all(output).context("write broker response")?;
    stream.flush().context("flush broker response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_client::probe_at;
    use std::path::PathBuf;

    struct SigningBackend;

    impl CapabilityBackend for SigningBackend {
        fn github_token(
            &self,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub request")
        }

        fn gh_token(
            &self,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub request")
        }

        fn invalidate_github_token(
            &self,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<()> {
            bail!("unexpected GitHub request")
        }

        fn sign_release_manifest(
            &self,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionReleaseSigningGrant,
            payload: &[u8],
        ) -> Result<Vec<u8>> {
            Ok(payload.to_vec())
        }

        fn sign_ssh(
            &self,
            _session_id: &str,
            _purpose: SshOperationPurpose,
            _grant: &crate::linux_admission::SessionOperationKeyGrant,
            payload: &[u8],
        ) -> Result<Vec<u8>> {
            Ok(payload.to_vec())
        }

        fn revoke_session(&self, _session_id: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn empty_registry_returns_explicit_no_session() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let registry = Arc::new(LinuxSessionRegistry::new());
        let server_registry = Arc::clone(&registry);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_public_connection(&mut stream, &server_registry, &UnavailableCapabilityBackend)
                .unwrap();
        });
        assert_eq!(
            probe_at(&socket).unwrap(),
            crate::broker_protocol::BrokerSessionProbe::NoSession
        );
        server.join().unwrap();
    }

    #[test]
    fn user_only_broker_authenticates_the_native_peer_and_returns_its_fixed_session() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("user-broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let session = crate::linux_admission::VerifiedLinuxSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            execution_uid: nix::unistd::Uid::effective().as_raw(),
            workload: "codex".into(),
            profile: "automation".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                github: None,
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::new(),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
        };
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_user_connection(&mut stream, &session, &UnavailableCapabilityBackend).unwrap();
        });
        assert_eq!(
            probe_at(&socket).unwrap(),
            crate::broker_protocol::BrokerSessionProbe::Verified {
                session_id: "0123456789abcdef0123456789abcdef".into(),
                owner_uid: nix::unistd::Uid::effective().as_raw(),
                execution_uid: nix::unistd::Uid::effective().as_raw(),
                workload: "codex".into(),
                profile: "automation".into(),
            }
        );
        server.join().unwrap();
    }

    #[test]
    fn session_resource_authority_is_exact_and_case_insensitive() {
        let session = crate::linux_admission::VerifiedLinuxSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: 1000,
            execution_uid: 991,
            workload: "codex".into(),
            profile: "automation".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                github: Some(crate::linux_admission::SessionGitHubGrant {
                    credential_slot: "automation".into(),
                    app_id: 42,
                    private_key_ref: "op://Automation/app/private-key".into(),
                    owners: vec!["ExampleOrg".into()],
                    repositories: vec!["api".into()],
                    permissions: std::collections::BTreeMap::from([(
                        "contents".into(),
                        crate::policy_v2::Permission::Write,
                    )]),
                    installation_ids: vec![],
                }),
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: "/sys/fs/cgroup/system.slice/dev-auth-workload-0123456789abcdef0123456789abcdef.service".into(),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
        };
        assert!(session_authorizes(
            &session,
            &BrokerRequest::GhExecutionToken
        ));
        assert!(!session_authorizes(
            &session,
            &BrokerRequest::GitCredential {
                protocol: "https".into(),
                host: "github.com".into(),
                owner: "exampleorg".into(),
                repository: "other".into(),
            }
        ));
    }

    #[test]
    fn signing_request_uses_only_the_session_bound_operation_key() {
        let key = crate::linux_admission::SessionOperationKeyGrant {
            credential_slot: "automation".into(),
            private_key_ref: "op://Automation/signing/private-key".into(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ dev-auth-policy-test".into(),
            fingerprint: "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI".into(),
        };
        let session = crate::linux_admission::VerifiedLinuxSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: 1000,
            execution_uid: 991,
            workload: "codex".into(),
            profile: "automation".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                github: None,
                signing: Some(key.clone()),
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::new(),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
        };
        assert_eq!(
            session_response(
                &session,
                BrokerRequest::SignSsh {
                    profile: "automation".into(),
                    purpose: SshOperationPurpose::GitSigning,
                    public_key_fingerprint: key.fingerprint.clone(),
                    payload: vec![1, 2, 3],
                },
                None,
                &SigningBackend,
            )
            .unwrap(),
            BrokerResponse::Signature {
                signature: vec![1, 2, 3]
            }
        );
        assert!(matches!(
            session_response(
                &session,
                BrokerRequest::SignSsh {
                    profile: "automation".into(),
                    purpose: SshOperationPurpose::GitSigning,
                    public_key_fingerprint:
                        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    payload: vec![1, 2, 3],
                },
                None,
                &SigningBackend,
            )
            .unwrap(),
            BrokerResponse::Denied { code, .. } if code == "resource_denied"
        ));
    }

    #[test]
    fn release_manifest_signing_rejects_git_signing_and_ungranted_products() {
        let key = crate::linux_admission::SessionOperationKeyGrant {
            credential_slot: "automation".into(),
            private_key_ref: "op://Automation/release/private-key".into(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuruylR5Dw9TRBXnt/aS8+Sj1dH3mUEcqFz8iItXZaZ dev-auth-policy-test".into(),
            fingerprint: "SHA256:5QH+7oUNO/MqyIzx8cLnowDLL1ZieiobwK9fp361KnI".into(),
        };
        let payload = serde_jcs::to_vec(&serde_json::json!({
            "schema": "dev-auth-product-v2",
            "product": "dev-auth",
            "generation": 17,
            "version": "0.3.6",
            "source_commit": "a".repeat(40),
            "engine_protocol": 1,
            "artifacts": {"linux-x86_64": {
                "url": "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.3.6/dev-auth-0.3.6-linux-x86_64",
                "length": 42,
                "sha256": "b".repeat(64),
            }}
        }))
        .unwrap();
        let mut session = crate::linux_admission::VerifiedLinuxSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: 1000,
            execution_uid: 991,
            workload: "release-agent".into(),
            profile: "release".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                github: None,
                signing: Some(key.clone()),
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::new(),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
        };
        let request = || BrokerRequest::SignReleaseManifest {
            profile: "release".into(),
            release_public_key: "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072"
                .into(),
            payload: payload.clone(),
        };
        assert!(matches!(
            session_response(&session, request(), None, &SigningBackend).unwrap(),
            BrokerResponse::Denied { code, .. } if code == "resource_denied"
        ));

        session.authority.signing = None;
        session.authority.release_signing =
            Some(crate::linux_admission::SessionReleaseSigningGrant {
                credential_slot: key.credential_slot.clone(),
                private_key_ref: "op://Automation/release/private-key".into(),
                public_key: "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072"
                    .into(),
                products: vec!["update-all".into()],
            });
        assert!(matches!(
            session_response(&session, request(), None, &SigningBackend).unwrap(),
            BrokerResponse::Denied { code, .. } if code == "resource_denied"
        ));
        session.authority.release_signing.as_mut().unwrap().products = vec!["dev-auth".into()];
        assert_eq!(
            session_response(&session, request(), None, &SigningBackend).unwrap(),
            BrokerResponse::Signature { signature: payload }
        );
    }

    #[test]
    fn audit_records_are_value_free_and_never_serialize_capability_material() {
        let request = BrokerRequest::SignSsh {
            profile: "release".into(),
            purpose: SshOperationPurpose::GitSigning,
            public_key_fingerprint: "SHA256:public-fingerprint".into(),
            payload: b"private-payload-sentinel".to_vec(),
        };
        let response = BrokerResponse::Signature {
            signature: b"private-signature-sentinel".to_vec(),
        };
        let json = serde_json::to_string(&request_audit_record(None, &request, &response)).unwrap();
        assert!(json.contains("git_signing"));
        assert!(json.contains("signature_issued"));
        assert!(!json.contains("private-payload-sentinel"));
        assert!(!json.contains("private-signature-sentinel"));
        assert!(!json.contains("public-fingerprint"));

        let request = BrokerRequest::GitCredential {
            protocol: "https".into(),
            host: "github.com".into(),
            owner: "private-owner-sentinel".into(),
            repository: "private-repository-sentinel".into(),
        };
        let response = BrokerResponse::GitCredential {
            username: "x-access-token".into(),
            password: crate::broker_protocol::SensitiveString::new("private-token-sentinel".into()),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&request_audit_record(None, &request, &response)).unwrap();
        assert!(!json.contains("private-owner-sentinel"));
        assert!(!json.contains("private-repository-sentinel"));
        assert!(!json.contains("private-token-sentinel"));
    }
}
