use crate::broker_backend::{
    CapabilityBackend, SystemCapabilityBackend, SESSION_CLEANUP_ATTEMPT_TIMEOUT,
};
use crate::broker_protocol::{
    decode_request_frame, encode_response_frame, BrokerRequest, BrokerResponse,
    BrokerResponseEnvelope, SshOperationPurpose, BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES,
};
use crate::control_protocol::{
    decode_control_request, encode_control_response, ControlRequest, ControlResponse,
    ControlResponseEnvelope,
};
use crate::linux_admission::{peer_evidence, LinuxSessionRegistry};
use crate::provider_operation::ProviderOperation;
use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockname, getsockopt, sockopt, UnixAddr};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const SYSTEM_CONTROL_SOCKET: &str = "/run/dev-auth/control.sock";
const PUBLIC_WORKERS: usize = 8;
const PUBLIC_QUEUE: usize = 64;
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct SessionOperations {
    // This gate pairs registry membership changes with operation admission. It
    // is released before provider calls and response I/O; those are coordinated
    // only by the affected session's state below.
    sessions: Mutex<BTreeMap<String, Arc<SessionOperationState>>>,
}

struct SessionOperationState {
    status: Mutex<SessionOperationStatus>,
    changed: Condvar,
    cancellation_requested: AtomicBool,
}

struct SessionOperationStatus {
    phase: SessionOperationPhase,
    in_flight: usize,
    close_deadline: Option<Instant>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SessionOperationPhase {
    Open,
    Closing,
    CleanupFailed,
    Closed,
}

struct SessionOperationGuard {
    state: Arc<SessionOperationState>,
}

struct SessionClose {
    session_id: String,
    state: Arc<SessionOperationState>,
    role: SessionCloseRole,
    existed: bool,
}

#[derive(Clone, Copy)]
enum SessionCloseRole {
    Owner,
    Waiter,
}

enum PeerSessionEnd {
    NoSession,
    Mismatch(crate::linux_admission::VerifiedLinuxSession),
    Closing(crate::linux_admission::VerifiedLinuxSession, SessionClose),
}

impl SessionOperationState {
    fn open() -> Self {
        Self {
            status: Mutex::new(SessionOperationStatus {
                phase: SessionOperationPhase::Open,
                in_flight: 0,
                close_deadline: None,
            }),
            changed: Condvar::new(),
            cancellation_requested: AtomicBool::new(false),
        }
    }

    fn closing() -> Self {
        Self {
            status: Mutex::new(SessionOperationStatus {
                phase: SessionOperationPhase::Closing,
                in_flight: 0,
                close_deadline: Instant::now().checked_add(SESSION_CLEANUP_ATTEMPT_TIMEOUT),
            }),
            changed: Condvar::new(),
            cancellation_requested: AtomicBool::new(true),
        }
    }

    fn admit(self: &Arc<Self>) -> Result<Option<SessionOperationGuard>> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        if status.phase != SessionOperationPhase::Open {
            return Ok(None);
        }
        status.in_flight = status
            .in_flight
            .checked_add(1)
            .context("session operation count overflowed")?;
        Ok(Some(SessionOperationGuard {
            state: Arc::clone(self),
        }))
    }

    fn is_open(&self) -> Result<bool> {
        let status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        Ok(status.phase == SessionOperationPhase::Open
            && !self.cancellation_requested.load(Ordering::Acquire))
    }

    fn start_close(&self) -> Result<SessionCloseRole> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        match status.phase {
            SessionOperationPhase::Open | SessionOperationPhase::CleanupFailed => {
                self.cancellation_requested.store(true, Ordering::Release);
                status.phase = SessionOperationPhase::Closing;
                status.close_deadline = Some(
                    Instant::now()
                        .checked_add(SESSION_CLEANUP_ATTEMPT_TIMEOUT)
                        .context("session close deadline overflowed")?,
                );
                Ok(SessionCloseRole::Owner)
            }
            SessionOperationPhase::Closing | SessionOperationPhase::Closed => {
                Ok(SessionCloseRole::Waiter)
            }
        }
    }

    fn start_cleanup_retry(&self) -> Result<bool> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        if status.phase != SessionOperationPhase::CleanupFailed {
            return Ok(false);
        }
        self.cancellation_requested.store(true, Ordering::Release);
        status.phase = SessionOperationPhase::Closing;
        status.close_deadline = Some(
            Instant::now()
                .checked_add(SESSION_CLEANUP_ATTEMPT_TIMEOUT)
                .context("session close deadline overflowed")?,
        );
        Ok(true)
    }

    fn cleanup_failed(&self) -> Result<bool> {
        let status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        Ok(status.phase == SessionOperationPhase::CleanupFailed)
    }

    fn wait_until_drained(&self) -> Result<Instant> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        while status.in_flight != 0 {
            let deadline = status
                .close_deadline
                .context("session close has no cleanup deadline")?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("session close timed out while draining operations")?;
            let (next, timeout) = self
                .changed
                .wait_timeout(status, remaining)
                .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
            status = next;
            if timeout.timed_out() && status.in_flight != 0 {
                bail!("session close timed out while draining operations");
            }
        }
        let deadline = status
            .close_deadline
            .context("session close has no cleanup deadline")?;
        if deadline <= Instant::now() {
            bail!("session close timed out before provider cleanup");
        }
        Ok(deadline)
    }

    fn finish_close(&self, succeeded: bool) -> Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        status.phase = if succeeded {
            SessionOperationPhase::Closed
        } else {
            SessionOperationPhase::CleanupFailed
        };
        status.close_deadline = None;
        self.changed.notify_all();
        Ok(())
    }

    fn wait_for_close(&self) -> Result<bool> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
        while status.phase == SessionOperationPhase::Closing {
            let deadline = status
                .close_deadline
                .context("session close has no cleanup deadline")?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("session close attempt timed out")?;
            let (next, timeout) = self
                .changed
                .wait_timeout(status, remaining)
                .map_err(|_| anyhow::anyhow!("session operation lock is poisoned"))?;
            status = next;
            if timeout.timed_out() && status.phase == SessionOperationPhase::Closing {
                bail!("session close attempt timed out");
            }
        }
        Ok(status.phase == SessionOperationPhase::Closed)
    }
}

impl SessionOperationGuard {
    fn provider_operation(&self) -> Result<ProviderOperation<'_>> {
        ProviderOperation::new(&self.state.cancellation_requested)
    }

    fn commit_publication(&self) -> Result<bool> {
        // start_close uses the same lock. Whichever transition wins defines
        // whether this result may be written; the guard remains live through
        // that write so a committed response is drained before cleanup.
        if self.cancellation_requested() {
            return Ok(false);
        }
        self.state.is_open()
    }

    fn cancellation_requested(&self) -> bool {
        self.state.cancellation_requested.load(Ordering::Acquire)
    }
}

impl Drop for SessionOperationGuard {
    fn drop(&mut self) {
        let mut status = self
            .state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if status.in_flight == 0 {
            return;
        }
        status.in_flight -= 1;
        if status.in_flight == 0 {
            self.state.changed.notify_all();
        }
    }
}

impl SessionOperations {
    fn open_session<T>(&self, session_id: &str, open: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        if sessions.contains_key(session_id) {
            bail!("session operations are already open or closing");
        }
        let opened = open()?;
        sessions.insert(
            session_id.to_owned(),
            Arc::new(SessionOperationState::open()),
        );
        Ok(opened)
    }

    fn with_available_session_id<T>(
        &self,
        session_id: &str,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        if sessions.contains_key(session_id) {
            bail!("session operations are already open or closing");
        }
        action()
    }

    fn with_open_session_id<T>(
        &self,
        session_id: &str,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        let state = sessions
            .get(session_id)
            .context("session operation state is unavailable")?;
        if !state.is_open()? {
            bail!("session operations are closing");
        }
        action()
    }

    #[cfg(test)]
    fn admit_session(&self, session_id: &str) -> Result<Option<SessionOperationGuard>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        let state = sessions
            .get(session_id)
            .context("session operation state is unavailable")?;
        state.admit()
    }

    fn with_open_peer<T>(
        &self,
        registry: &LinuxSessionRegistry,
        peer: &crate::linux_admission::LinuxPeerEvidence,
        action: impl FnOnce(&crate::linux_admission::VerifiedLinuxSession) -> Result<T>,
    ) -> Result<Option<(crate::linux_admission::VerifiedLinuxSession, T)>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        let Some(session) = registry.probe_peer(peer)? else {
            return Ok(None);
        };
        let state = sessions
            .get(&session.session_id)
            .context("session operation state is unavailable")?;
        if !state.is_open()? {
            bail!("session operations are closing");
        }
        let result = action(&session)?;
        Ok(Some((session, result)))
    }

    fn admit_peer_operation(
        &self,
        registry: &LinuxSessionRegistry,
        peer: &crate::linux_admission::LinuxPeerEvidence,
    ) -> Result<
        Option<(
            crate::linux_admission::VerifiedLinuxSession,
            SessionOperationGuard,
        )>,
    > {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        let Some(session) = registry.probe_peer(peer)? else {
            return Ok(None);
        };
        let state = sessions
            .get(&session.session_id)
            .context("session operation state is unavailable")?;
        let operation = state.admit()?.context("session operations are closing")?;
        Ok(Some((session, operation)))
    }

    fn begin_close(
        &self,
        session_id: &str,
        revoke_registry: impl FnOnce() -> Result<bool>,
    ) -> Result<Option<SessionClose>> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        Self::begin_close_locked(&mut sessions, session_id, revoke_registry)
    }

    fn begin_close_locked(
        sessions: &mut BTreeMap<String, Arc<SessionOperationState>>,
        session_id: &str,
        revoke_registry: impl FnOnce() -> Result<bool>,
    ) -> Result<Option<SessionClose>> {
        let existing = sessions.get(session_id).cloned();
        let state = existing
            .clone()
            .unwrap_or_else(|| Arc::new(SessionOperationState::closing()));
        let role = if existing.is_some() {
            state.start_close()?
        } else {
            sessions.insert(session_id.to_owned(), Arc::clone(&state));
            SessionCloseRole::Owner
        };
        if matches!(role, SessionCloseRole::Waiter) {
            return Ok(Some(SessionClose {
                session_id: session_id.to_owned(),
                state,
                role,
                // An operation-state entry means that this session either was
                // active or still has cleanup authority retained for retry.
                existed: existing.is_some(),
            }));
        }

        let existed = match revoke_registry() {
            Ok(existed) => existed,
            Err(error) => {
                state.finish_close(false)?;
                return Err(error);
            }
        };
        if existing.is_none() && !existed {
            state.finish_close(true)?;
            sessions.remove(session_id);
            return Ok(None);
        }
        Ok(Some(SessionClose {
            session_id: session_id.to_owned(),
            state,
            role,
            existed,
        }))
    }

    fn begin_peer_end(
        &self,
        registry: &LinuxSessionRegistry,
        peer: &crate::linux_admission::LinuxPeerEvidence,
        requested_session_id: &str,
    ) -> Result<PeerSessionEnd> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        let Some(session) = registry.probe_peer(peer)? else {
            return Ok(PeerSessionEnd::NoSession);
        };
        if session.session_id != requested_session_id {
            return Ok(PeerSessionEnd::Mismatch(session));
        }
        let close = Self::begin_close_locked(&mut sessions, requested_session_id, || {
            registry.revoke(requested_session_id)
        })?
        .context("verified session disappeared before teardown")?;
        Ok(PeerSessionEnd::Closing(session, close))
    }

    fn begin_reaper_closes(&self, registry: &LinuxSessionRegistry) -> Result<Vec<SessionClose>> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        let stale = registry.prune_stale()?;
        let mut closes = Vec::with_capacity(stale.len());
        for session_id in stale {
            let state = sessions
                .entry(session_id.clone())
                .or_insert_with(|| Arc::new(SessionOperationState::open()))
                .clone();
            let role = state.start_close()?;
            closes.push(SessionClose {
                session_id,
                state,
                role,
                existed: true,
            });
        }
        let mut retry_ids = Vec::new();
        for (session_id, state) in sessions.iter() {
            if state.cleanup_failed()? {
                retry_ids.push(session_id.clone());
            }
        }
        for session_id in retry_ids {
            registry.revoke(&session_id)?;
            let state = sessions
                .get(&session_id)
                .context("cleanup retry state disappeared")?;
            if state.start_cleanup_retry()? {
                closes.push(SessionClose {
                    session_id,
                    state: Arc::clone(state),
                    role: SessionCloseRole::Owner,
                    existed: true,
                });
            }
        }
        Ok(closes)
    }

    fn complete_close(&self, close: SessionClose, backend: &dyn CapabilityBackend) -> Result<bool> {
        if matches!(close.role, SessionCloseRole::Waiter) {
            if close.state.wait_for_close()? {
                return Ok(close.existed);
            }
            bail!("session capability cleanup failed");
        }

        let deadline = match close.state.wait_until_drained() {
            Ok(deadline) => deadline,
            Err(error) => {
                close.state.finish_close(false)?;
                return Err(error);
            }
        };
        let cleanup = backend.revoke_session_before(&close.session_id, deadline);
        close.state.finish_close(cleanup.is_ok())?;
        cleanup?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session operations registry lock is poisoned"))?;
        if sessions
            .get(&close.session_id)
            .is_some_and(|state| Arc::ptr_eq(state, &close.state))
        {
            sessions.remove(&close.session_id);
        }
        Ok(close.existed)
    }
}

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
        let _ = handle_user_connection(&mut stream, &session, &backend, stop.as_ref());
    }
    let deadline = Instant::now()
        .checked_add(SESSION_CLEANUP_ATTEMPT_TIMEOUT)
        .context("user-session cleanup deadline overflowed")?;
    let result = backend.revoke_session_before(&session.session_id, deadline);
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
    stop: &AtomicBool,
) -> Result<()> {
    let credentials = getsockopt(stream, sockopt::PeerCredentials)
        .context("read user broker peer credentials")?;
    if credentials.uid() != session.owner_uid || credentials.pid() <= 0 {
        bail!("user broker peer is outside the documented same-user trust boundary");
    }
    let request = decode_request_frame(&read_frame(stream)?)?;
    let audit_request = request.request.clone();
    let operation = ProviderOperation::new(stop)?;
    let response = session_response(&operation, session, request.request, backend)?;
    write_user_response(
        stream,
        session,
        &audit_request,
        request.request_id,
        response,
        stop,
    )
}

fn write_user_response(
    stream: &mut UnixStream,
    session: &crate::linux_admission::VerifiedLinuxSession,
    audit_request: &BrokerRequest,
    request_id: String,
    mut response: BrokerResponse,
    stop: &AtomicBool,
) -> Result<()> {
    if stop.load(Ordering::Acquire) {
        response = session_closing_denial();
    }
    emit_request_audit(Some(session), audit_request, &response);
    write_frame(
        stream,
        &encode_response_frame(&BrokerResponseEnvelope {
            version: BROKER_PROTOCOL_VERSION,
            request_id,
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
    let operations = Arc::new(SessionOperations::default());
    let control_registry = Arc::clone(&registry);
    let control_operations = Arc::clone(&operations);
    let control_backend = Arc::clone(&backend);
    thread::Builder::new()
        .name("dev-auth-control".into())
        .spawn(move || {
            control_accept_loop(
                control_listener,
                control_registry,
                control_operations,
                control_backend,
            )
        })
        .context("start broker control listener")?;
    let reaper_registry = Arc::clone(&registry);
    let reaper_operations = Arc::clone(&operations);
    let reaper_backend = Arc::clone(&backend);
    thread::Builder::new()
        .name("dev-auth-session-reaper".into())
        .spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            if let Err(error) = revoke_stale_sessions(
                &reaper_registry,
                &reaper_operations,
                reaper_backend.as_ref(),
            ) {
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
        let worker_operations = Arc::clone(&operations);
        let worker_backend = Arc::clone(&backend);
        thread::Builder::new()
            .name(format!("dev-auth-public-{index}"))
            .spawn(move || {
                public_worker(
                    worker_receiver,
                    worker_registry,
                    worker_operations,
                    worker_backend,
                )
            })
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
        _operation: &ProviderOperation<'_>,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionGitHubGrant,
        _owner: &str,
        _repository: &str,
    ) -> Result<crate::runtime::BrokerGitHubToken> {
        bail!("capability backend is unavailable")
    }

    fn gh_token(
        &self,
        _operation: &ProviderOperation<'_>,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionGitHubGrant,
    ) -> Result<crate::runtime::BrokerGitHubToken> {
        bail!("capability backend is unavailable")
    }

    fn invalidate_github_token(
        &self,
        _operation: &ProviderOperation<'_>,
        _session_id: &str,
        _grant: &crate::linux_admission::SessionGitHubGrant,
        _owner: &str,
        _repository: &str,
    ) -> Result<()> {
        bail!("capability backend is unavailable")
    }

    fn sign_ssh(
        &self,
        _operation: &ProviderOperation<'_>,
        _session_id: &str,
        _purpose: SshOperationPurpose,
        _grant: &crate::linux_admission::SessionOperationKeyGrant,
        _payload: &[u8],
    ) -> Result<Vec<u8>> {
        bail!("capability backend is unavailable")
    }

    fn sign_release_manifest(
        &self,
        _operation: &ProviderOperation<'_>,
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
    if std::env::var("LISTEN_FDS").as_deref() != Ok("2") {
        bail!("system broker requires the exact public and control socket units");
    }
    let names = std::env::var("LISTEN_FDNAMES")
        .context("systemd did not provide the broker listener names")?;
    let (public_fd, control_fd) = listener_fds_for_names(&names)?;
    validate_inherited_listener(
        public_fd,
        Path::new(crate::broker_client::SYSTEM_BROKER_SOCKET),
        0o666,
    )?;
    validate_inherited_listener(control_fd, Path::new(SYSTEM_CONTROL_SOCKET), 0o600)?;
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    // SAFETY: systemd's socket-activation contract gives this process ownership
    // of exactly descriptors 3 and 4. The exact PID/count/name set was checked,
    // each distinct descriptor was successfully queried at its required
    // root-owned Unix socket path, and no safe owner exists in this process.
    // Converting each descriptor once transfers ownership to `UnixListener`,
    // whose destructor closes it.
    let public = unsafe { UnixListener::from_raw_fd(public_fd) };
    // SAFETY: the same validated contract applies to the distinct control
    // descriptor selected from the exact two-name set and converted once.
    let control = unsafe { UnixListener::from_raw_fd(control_fd) };
    Ok((public, control))
}

fn listener_fds_for_names(names: &str) -> Result<(i32, i32)> {
    match names {
        "public:control" => Ok((3, 4)),
        "control:public" => Ok((4, 3)),
        _ => bail!("system broker requires the exact public and control socket units"),
    }
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
    operations: Arc<SessionOperations>,
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
        let _ = handle_public_connection(&mut stream, &registry, &operations, backend.as_ref());
    }
}

fn handle_public_connection(
    stream: &mut UnixStream,
    registry: &LinuxSessionRegistry,
    operations: &SessionOperations,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
    let peer = peer_evidence(stream)?;
    let request_bytes = read_frame(stream)?;
    let request = decode_request_frame(&request_bytes)?;
    let audit_request = request.request.clone();
    let (mut response, audit_session, operation) = match request.request {
        BrokerRequest::ActivateSession { session_id } => {
            let response = match operations
                .open_session(&session_id, || registry.activate_pending(peer, &session_id))
            {
                Ok(session) => ready_response(&session)?,
                Err(_) => BrokerResponse::Denied {
                    code: "session_invalid".into(),
                    message: "pending workload admission could not be activated".into(),
                },
            };
            (response, None, None)
        }
        BrokerRequest::EndSession { session_id } => {
            match operations.begin_peer_end(registry, &peer, &session_id) {
                Ok(PeerSessionEnd::NoSession) => (no_session_denial(), None, None),
                Ok(PeerSessionEnd::Mismatch(session)) => (
                    BrokerResponse::Denied {
                        code: "session_invalid".into(),
                        message: "session teardown does not match the admitted workload".into(),
                    },
                    Some(session),
                    None,
                ),
                Ok(PeerSessionEnd::Closing(session, close)) => {
                    operations.complete_close(close, backend)?;
                    (BrokerResponse::Accepted, Some(session), None)
                }
                Err(_) => (session_verification_denial(), None, None),
            }
        }
        BrokerRequest::RenewSession { session_id } => {
            match operations.with_open_peer(registry, &peer, |session| {
                if session.session_id != session_id {
                    return Ok(BrokerResponse::Denied {
                        code: "session_invalid".into(),
                        message: "session renewal does not match the admitted workload".into(),
                    });
                }
                registry.renew(&session_id, lease_expiry())?;
                Ok(BrokerResponse::Accepted)
            }) {
                Ok(Some((session, response))) => (response, Some(session), None),
                Ok(None) => (no_session_denial(), None, None),
                Err(_) => (session_verification_denial(), None, None),
            }
        }
        BrokerRequest::Probe => match operations.with_open_peer(registry, &peer, ready_response) {
            Ok(Some((session, response))) => (response, Some(session), None),
            Ok(None) => (BrokerResponse::NoSession, None, None),
            Err(_) => (session_verification_denial(), None, None),
        },
        capability => match operations.admit_peer_operation(registry, &peer) {
            Ok(Some((session, operation))) => {
                let provider_operation = operation.provider_operation()?;
                let response =
                    session_response(&provider_operation, &session, capability, backend)?;
                (response, Some(session), Some(operation))
            }
            Ok(None) => (no_session_denial(), None, None),
            Err(_) => (session_verification_denial(), None, None),
        },
    };
    if let Some(operation) = operation.as_ref() {
        if !operation.commit_publication()? {
            response = session_closing_denial();
        }
    }
    let audit_record = request_audit_record(audit_session.as_ref(), &audit_request, &response);
    let output = encode_response_frame(&BrokerResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request.request_id,
        response,
    })?;
    write_public_response(stream, &output, operation, || {
        emit_request_audit_record(&audit_record)
    })
}

fn write_public_response(
    stream: &mut UnixStream,
    output: &[u8],
    operation: Option<SessionOperationGuard>,
    emit_audit: impl FnOnce(),
) -> Result<()> {
    let result = write_frame(stream, output);
    // Response publication is part of the admitted operation. Release that
    // operation before emitting to stderr: a blocked journal consumer must not
    // pin session cleanup. Audit records can consequently appear after a later
    // lifecycle record; their session/capability/resource fields correlate the
    // completed request without retaining capability material.
    drop(operation);
    emit_audit();
    result
}

fn session_response(
    operation: &ProviderOperation<'_>,
    session: &crate::linux_admission::VerifiedLinuxSession,
    request: BrokerRequest,
    backend: &dyn CapabilityBackend,
) -> Result<BrokerResponse> {
    let response = match request {
        BrokerRequest::Probe => ready_response(session)?,
        BrokerRequest::ActivateSession { .. } => BrokerResponse::Denied {
            code: "session_invalid".into(),
            message: "an active workload cannot activate another admission".into(),
        },
        BrokerRequest::RenewSession { .. } => BrokerResponse::Denied {
            code: "session_invalid".into(),
            message: "session renewal does not match the admitted workload".into(),
        },
        BrokerRequest::EndSession { .. } => BrokerResponse::Denied {
            code: "session_invalid".into(),
            message: "session teardown does not match the admitted workload".into(),
        },
        operation if !session_authorizes(session, &operation) => BrokerResponse::Denied {
            code: "resource_denied".into(),
            message: "workload profile does not authorize the requested capability".into(),
        },
        BrokerRequest::GitCredential {
            owner, repository, ..
        } => github_token_response(
            operation,
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
                operation,
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
            Some(grant) => match backend.gh_token(operation, &session.session_id, grant) {
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
            Some(grant) => {
                match backend.sign_ssh(operation, &session.session_id, purpose, grant, &payload) {
                    Ok(signature) => BrokerResponse::Signature { signature },
                    Err(_) => provider_denial(),
                }
            }
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
                match dev_tools_release::validate_unsigned_release_document(&payload) {
                    Ok(document) if grant.products.contains(&document.authority) => match backend
                        .sign_release_manifest(operation, &session.session_id, grant, &payload)
                    {
                        Ok(signature) => BrokerResponse::Signature { signature },
                        Err(_) => provider_denial(),
                    },
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
    emit_request_audit_record(&record);
}

fn emit_request_audit_record(record: &BrokerAuditRecord<'_>) {
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
            let product = dev_tools_release::validate_unsigned_release_document(payload)
                .map(|document| document.authority)
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
    operation: &ProviderOperation<'_>,
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
    match backend.github_token(operation, &session.session_id, grant, owner, repository) {
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

fn no_session_denial() -> BrokerResponse {
    BrokerResponse::Denied {
        code: "no_session".into(),
        message: "caller is outside a registered workload session".into(),
    }
}

fn session_verification_denial() -> BrokerResponse {
    BrokerResponse::Denied {
        code: "session_invalid".into(),
        message: "workload session admission could not be verified".into(),
    }
}

fn session_closing_denial() -> BrokerResponse {
    BrokerResponse::Denied {
        code: "session_invalid".into(),
        message: "workload session teardown has started".into(),
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
                            && dev_tools_release::validate_unsigned_release_document(payload)
                                .is_ok_and(|document| grant.products.contains(&document.authority))
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
    operations: Arc<SessionOperations>,
    backend: Arc<dyn CapabilityBackend>,
) {
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            return;
        };
        // The control peer is authenticated before parsing. Malformed or
        // unauthenticated input is closed without an oracle over broker internals.
        let _ = handle_control_connection(&mut stream, &registry, &operations, backend.as_ref());
    }
}

fn handle_control_connection(
    stream: &mut UnixStream,
    registry: &LinuxSessionRegistry,
    operations: &SessionOperations,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
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
        ControlRequest::Prepare { session } => {
            let session_id = session.session_id.clone();
            match operations
                .with_available_session_id(&session_id, || registry.prepare_root_owned(*session))
            {
                Ok(()) => ControlResponse::Accepted,
                Err(_) => ControlResponse::Denied {
                    message: "pending session admission was rejected".into(),
                },
            }
        }
        ControlRequest::Register { session } => {
            let session_id = session.session_id.clone();
            match operations.open_session(&session_id, || {
                registry.register_root_owned(*session, peer_pidfd)
            }) {
                Ok(()) => ControlResponse::Accepted,
                Err(_) => ControlResponse::Denied {
                    message: "session registration was rejected".into(),
                },
            }
        }
        ControlRequest::Renew {
            session_id,
            expires_at_unix,
        } => {
            match operations
                .with_open_session_id(&session_id, || registry.renew(&session_id, expires_at_unix))
            {
                Ok(()) => ControlResponse::Accepted,
                Err(_) => ControlResponse::Denied {
                    message: "session renewal was rejected".into(),
                },
            }
        }
        ControlRequest::Revoke { session_id } => {
            let existed =
                match operations.begin_close(&session_id, || registry.revoke(&session_id))? {
                    Some(close) => operations.complete_close(close, backend)?,
                    None => false,
                };
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
    operations: &SessionOperations,
    backend: &dyn CapabilityBackend,
) -> Result<()> {
    let mut failed = false;
    for close in operations.begin_reaper_closes(registry)? {
        if operations.complete_close(close, backend).is_err() {
            failed = true;
        }
    }
    if failed {
        bail!("one or more stale sessions could not be cleaned up");
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
    read_frame_with_clock(stream, FRAME_IO_TIMEOUT, Instant::now)
}

fn read_frame_with_clock(
    stream: &mut UnixStream,
    timeout: Duration,
    mut now: impl FnMut() -> Instant,
) -> Result<Vec<u8>> {
    let deadline = now()
        .checked_add(timeout)
        .context("broker frame read deadline overflowed")?;
    let mut length = [0_u8; 4];
    read_exact_before(stream, &mut length, deadline, &mut now).context("read frame length")?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_BROKER_FRAME_BYTES {
        bail!("broker frame exceeds the size limit");
    }
    let mut input = vec![0_u8; length];
    read_exact_before(stream, &mut input, deadline, &mut now).context("read broker frame")?;
    Ok(input)
}

fn write_frame(stream: &mut UnixStream, output: &[u8]) -> Result<()> {
    write_frame_with_clock(stream, output, FRAME_IO_TIMEOUT, Instant::now)
}

fn write_frame_with_clock(
    stream: &mut UnixStream,
    output: &[u8],
    timeout: Duration,
    mut now: impl FnMut() -> Instant,
) -> Result<()> {
    if output.len() > MAX_BROKER_FRAME_BYTES {
        bail!("broker response exceeds the size limit");
    }
    let deadline = now()
        .checked_add(timeout)
        .context("broker frame write deadline overflowed")?;
    let length = u32::try_from(output.len()).context("broker response length is invalid")?;
    write_all_before(stream, &length.to_be_bytes(), deadline, &mut now)
        .context("write broker response length")?;
    write_all_before(stream, output, deadline, &mut now).context("write broker response")?;
    set_write_timeout_before(stream, deadline, &mut now)?;
    stream.flush().context("flush broker response")
}

fn read_exact_before(
    stream: &mut UnixStream,
    input: &mut [u8],
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < input.len() {
        let remaining = remaining_frame_time(deadline, now())?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut input[offset..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "broker peer closed before the frame completed",
                ));
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_before(
    stream: &mut UnixStream,
    output: &[u8],
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        let remaining = remaining_frame_time(deadline, now())?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(&output[offset..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "broker peer accepted no response bytes",
                ));
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn set_write_timeout_before(
    stream: &UnixStream,
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> Result<()> {
    let remaining = remaining_frame_time(deadline, now())?;
    stream
        .set_write_timeout(Some(remaining))
        .context("set broker frame write timeout")
}

fn remaining_frame_time(deadline: Instant, now: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "broker absolute frame deadline elapsed",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_client::probe_at;
    use std::path::PathBuf;

    struct SigningBackend;

    struct LateTokenBackend {
        provider_started: mpsc::Sender<()>,
        provider_release: Mutex<mpsc::Receiver<()>>,
        session_revoked: mpsc::Sender<String>,
    }

    struct RetryCleanupBackend {
        attempts: std::sync::atomic::AtomicUsize,
    }

    fn provider_operation() -> ProviderOperation<'static> {
        ProviderOperation::uncancelled().unwrap()
    }

    impl CapabilityBackend for LateTokenBackend {
        fn github_token(
            &self,
            operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            operation.checkpoint()?;
            self.provider_started.send(()).unwrap();
            self.provider_release.lock().unwrap().recv().unwrap();
            operation.checkpoint()?;
            Ok(crate::runtime::BrokerGitHubToken {
                token: crate::SecretString::new("late-installation-token".into()),
                expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
            })
        }

        fn gh_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub CLI request")
        }

        fn invalidate_github_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<()> {
            bail!("unexpected GitHub invalidation")
        }

        fn sign_ssh(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _purpose: SshOperationPurpose,
            _grant: &crate::linux_admission::SessionOperationKeyGrant,
            _payload: &[u8],
        ) -> Result<Vec<u8>> {
            bail!("unexpected SSH signing request")
        }

        fn sign_release_manifest(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionReleaseSigningGrant,
            _payload: &[u8],
        ) -> Result<Vec<u8>> {
            bail!("unexpected release-signing request")
        }

        fn revoke_session(&self, session_id: &str) -> Result<()> {
            self.session_revoked.send(session_id.to_owned()).unwrap();
            Ok(())
        }
    }

    impl CapabilityBackend for RetryCleanupBackend {
        fn github_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub request")
        }

        fn gh_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub CLI request")
        }

        fn invalidate_github_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<()> {
            bail!("unexpected GitHub invalidation")
        }

        fn sign_ssh(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _purpose: SshOperationPurpose,
            _grant: &crate::linux_admission::SessionOperationKeyGrant,
            _payload: &[u8],
        ) -> Result<Vec<u8>> {
            bail!("unexpected SSH signing request")
        }

        fn sign_release_manifest(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionReleaseSigningGrant,
            _payload: &[u8],
        ) -> Result<Vec<u8>> {
            bail!("unexpected release-signing request")
        }

        fn revoke_session(&self, _session_id: &str) -> Result<()> {
            let attempt = self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt == 0 {
                bail!("injected first cleanup failure");
            }
            Ok(())
        }
    }

    fn github_session(session_id: &str) -> crate::linux_admission::VerifiedLinuxSession {
        crate::linux_admission::VerifiedLinuxSession {
            session_id: session_id.into(),
            owner_uid: 1000,
            execution_uid: 991,
            workload: "codex".into(),
            profile: "automation".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                github: Some(crate::linux_admission::SessionGitHubGrant {
                    credential_slot: "automation".into(),
                    app_id: 42,
                    repository_selection: crate::RepositorySelection::Selected,
                    private_key_ref: "op://Automation/app/private-key".into(),
                    owners: vec!["ExampleOrg".into()],
                    repositories: vec!["api".into()],
                    permissions: std::collections::BTreeMap::from([(
                        "contents".into(),
                        crate::policy_v2::Permission::Read,
                    )]),
                    installation_ids: Vec::new(),
                }),
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::new(),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
        }
    }

    #[test]
    fn closing_session_rejects_late_provider_result_and_revokes_before_acknowledgement() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let operations = Arc::new(SessionOperations::default());
        operations.open_session(session_id, || Ok(())).unwrap();
        let operation = operations.admit_session(session_id).unwrap().unwrap();
        let (provider_started, provider_started_rx) = mpsc::channel();
        let (provider_release, provider_release_rx) = mpsc::channel();
        let (session_revoked, session_revoked_rx) = mpsc::channel();
        let backend = Arc::new(LateTokenBackend {
            provider_started,
            provider_release: Mutex::new(provider_release_rx),
            session_revoked,
        });
        let worker_backend = Arc::clone(&backend);
        let session = github_session(session_id);
        let worker = thread::spawn(move || {
            let provider_operation = operation.provider_operation().unwrap();
            let response = session_response(
                &provider_operation,
                &session,
                BrokerRequest::GitCredential {
                    protocol: "https".into(),
                    host: "github.com".into(),
                    owner: "ExampleOrg".into(),
                    repository: "api".into(),
                },
                worker_backend.as_ref(),
            )
            .unwrap();
            if operation.commit_publication().unwrap() {
                response
            } else {
                session_closing_denial()
            }
        });

        provider_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let close = operations
            .begin_close(session_id, || Ok(true))
            .unwrap()
            .unwrap();
        assert!(operations.admit_session(session_id).unwrap().is_none());
        assert!(session_revoked_rx.try_recv().is_err());

        provider_release.send(()).unwrap();
        let response = worker.join().unwrap();
        assert!(matches!(
            response,
            BrokerResponse::Denied { code, .. } if code == "session_invalid"
        ));
        assert!(operations.complete_close(close, backend.as_ref()).unwrap());
        assert_eq!(
            session_revoked_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            session_id
        );
    }

    #[test]
    fn user_session_cancellation_after_provider_completion_suppresses_the_token_response() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let session = github_session(session_id);
        let stop = AtomicBool::new(false);
        let (provider_started, provider_started_rx) = mpsc::channel();
        let (provider_release, provider_release_rx) = mpsc::channel();
        provider_release.send(()).unwrap();
        let (session_revoked, _session_revoked_rx) = mpsc::channel();
        let backend = LateTokenBackend {
            provider_started,
            provider_release: Mutex::new(provider_release_rx),
            session_revoked,
        };
        let request = BrokerRequest::GitCredential {
            protocol: "https".into(),
            host: "github.com".into(),
            owner: "ExampleOrg".into(),
            repository: "api".into(),
        };
        let operation = ProviderOperation::new(&stop).unwrap();
        let response = session_response(&operation, &session, request.clone(), &backend).unwrap();
        provider_started_rx.try_recv().unwrap();
        assert!(matches!(response, BrokerResponse::GitCredential { .. }));

        stop.store(true, Ordering::Release);
        let (mut server, mut client) = UnixStream::pair().unwrap();
        write_user_response(
            &mut server,
            &session,
            &request,
            "abcdef0123456789abcdef0123456789".into(),
            response,
            &stop,
        )
        .unwrap();
        let response =
            crate::broker_protocol::decode_response_frame(&read_frame(&mut client).unwrap())
                .unwrap()
                .response;

        assert!(matches!(
            response,
            BrokerResponse::Denied { code, .. } if code == "session_invalid"
        ));
    }

    #[test]
    fn closing_one_session_does_not_block_another_sessions_operations() {
        let operations = SessionOperations::default();
        operations.open_session("session-a", || Ok(())).unwrap();
        operations.open_session("session-b", || Ok(())).unwrap();
        let first_operation = operations.admit_session("session-a").unwrap().unwrap();

        let close = operations
            .begin_close("session-a", || Ok(true))
            .unwrap()
            .unwrap();
        assert!(first_operation.cancellation_requested());
        assert!(first_operation
            .provider_operation()
            .unwrap()
            .checkpoint()
            .is_err());
        assert!(operations.admit_session("session-a").unwrap().is_none());
        let second_operation = operations.admit_session("session-b").unwrap().unwrap();

        drop(second_operation);
        drop(first_operation);
        assert!(operations
            .complete_close(close, &UnavailableCapabilityBackend)
            .unwrap());
    }

    #[test]
    fn one_close_deadline_bounds_drain_before_provider_cleanup() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let operations = SessionOperations::default();
        operations.open_session(session_id, || Ok(())).unwrap();
        let operation = operations.admit_session(session_id).unwrap().unwrap();
        let close = operations
            .begin_close(session_id, || Ok(true))
            .unwrap()
            .unwrap();
        {
            let mut status = close.state.status.lock().unwrap();
            status.close_deadline = Instant::now().checked_sub(Duration::from_secs(1));
        }

        assert!(operations
            .complete_close(close, &UnavailableCapabilityBackend)
            .is_err());
        assert!(operation.cancellation_requested());
        assert!(operations.admit_session(session_id).unwrap().is_none());
        drop(operation);
        revoke_stale_sessions(
            &LinuxSessionRegistry::new(),
            &operations,
            &UnavailableCapabilityBackend,
        )
        .unwrap();
    }

    #[test]
    fn failed_cleanup_remains_fail_closed_until_the_reaper_retry_succeeds() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let operations = SessionOperations::default();
        let registry = LinuxSessionRegistry::new();
        let backend = RetryCleanupBackend {
            attempts: std::sync::atomic::AtomicUsize::new(0),
        };
        operations.open_session(session_id, || Ok(())).unwrap();

        let close = operations
            .begin_close(session_id, || Ok(true))
            .unwrap()
            .unwrap();
        assert!(operations.complete_close(close, &backend).is_err());
        assert!(operations.admit_session(session_id).unwrap().is_none());

        revoke_stale_sessions(&registry, &operations, &backend).unwrap();
        assert_eq!(
            backend.attempts.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        operations.open_session(session_id, || Ok(())).unwrap();
    }

    #[test]
    fn request_entrypoints_do_not_run_failed_cleanup_inline() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let operations = Arc::new(SessionOperations::default());
        let registry = Arc::new(LinuxSessionRegistry::new());
        let backend = Arc::new(RetryCleanupBackend {
            attempts: std::sync::atomic::AtomicUsize::new(0),
        });
        operations.open_session(session_id, || Ok(())).unwrap();
        let close = operations
            .begin_close(session_id, || Ok(true))
            .unwrap()
            .unwrap();
        assert!(operations.complete_close(close, backend.as_ref()).is_err());

        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_registry = Arc::clone(&registry);
        let server_operations = Arc::clone(&operations);
        let server_backend = Arc::clone(&backend);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_public_connection(
                &mut stream,
                &server_registry,
                &server_operations,
                server_backend.as_ref(),
            )
            .unwrap();
        });
        assert_eq!(
            probe_at(&socket).unwrap(),
            crate::broker_protocol::BrokerSessionProbe::NoSession
        );
        server.join().unwrap();

        let (mut control, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&0_u32.to_be_bytes()).unwrap();
        assert!(
            handle_control_connection(&mut control, &registry, &operations, backend.as_ref(),)
                .is_err()
        );
        assert_eq!(
            backend.attempts.load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        revoke_stale_sessions(&registry, &operations, backend.as_ref()).unwrap();
    }

    #[test]
    fn public_response_releases_operation_before_audit_output() {
        let session_id = "0123456789abcdef0123456789abcdef";
        let operations = SessionOperations::default();
        operations.open_session(session_id, || Ok(())).unwrap();
        let operation = operations.admit_session(session_id).unwrap().unwrap();
        let state = Arc::clone(&operation.state);
        let (mut stream, _peer) = UnixStream::pair().unwrap();

        write_public_response(&mut stream, b"response", Some(operation), || {
            let status = state.status.lock().unwrap();
            assert_eq!(status.in_flight, 0);
        })
        .unwrap();
    }

    #[test]
    fn frame_io_uses_one_absolute_deadline_across_all_chunks() {
        let timeout = Duration::from_secs(2);
        let start = Instant::now();
        let deadline = start + timeout;
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&1_u32.to_be_bytes()).unwrap();
        writer.write_all(&[7]).unwrap();
        let mut read_times = std::collections::VecDeque::from([start, start, deadline]);
        let read_error =
            read_frame_with_clock(&mut reader, timeout, || read_times.pop_front().unwrap())
                .unwrap_err();
        assert!(format!("{read_error:#}").contains("absolute frame deadline elapsed"));

        let (mut writer, _reader) = UnixStream::pair().unwrap();
        let mut write_times = std::collections::VecDeque::from([start, start, deadline]);
        let write_error = write_frame_with_clock(&mut writer, b"x", timeout, || {
            write_times.pop_front().unwrap()
        })
        .unwrap_err();
        assert!(format!("{write_error:#}").contains("absolute frame deadline elapsed"));
    }

    #[test]
    fn systemd_listener_names_map_each_descriptor_by_role_regardless_of_order() {
        assert_eq!(listener_fds_for_names("public:control").unwrap(), (3, 4));
        assert_eq!(listener_fds_for_names("control:public").unwrap(), (4, 3));

        for names in [
            "public",
            "control",
            "public:public",
            "control:control",
            "public:other",
        ] {
            assert!(listener_fds_for_names(names).is_err(), "accepted {names}");
        }
    }

    impl CapabilityBackend for SigningBackend {
        fn github_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub request")
        }

        fn gh_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
        ) -> Result<crate::runtime::BrokerGitHubToken> {
            bail!("unexpected GitHub request")
        }

        fn invalidate_github_token(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionGitHubGrant,
            _owner: &str,
            _repository: &str,
        ) -> Result<()> {
            bail!("unexpected GitHub request")
        }

        fn sign_release_manifest(
            &self,
            _operation: &ProviderOperation<'_>,
            _session_id: &str,
            _grant: &crate::linux_admission::SessionReleaseSigningGrant,
            payload: &[u8],
        ) -> Result<Vec<u8>> {
            Ok(payload.to_vec())
        }

        fn sign_ssh(
            &self,
            _operation: &ProviderOperation<'_>,
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
            handle_public_connection(
                &mut stream,
                &server_registry,
                &SessionOperations::default(),
                &UnavailableCapabilityBackend,
            )
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
            handle_user_connection(
                &mut stream,
                &session,
                &UnavailableCapabilityBackend,
                &AtomicBool::new(false),
            )
            .unwrap();
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
                    repository_selection: crate::RepositorySelection::Selected,
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
                &provider_operation(),
                &session,
                BrokerRequest::SignSsh {
                    profile: "automation".into(),
                    purpose: SshOperationPurpose::GitSigning,
                    public_key_fingerprint: key.fingerprint.clone(),
                    payload: vec![1, 2, 3],
                },
                &SigningBackend,
            )
            .unwrap(),
            BrokerResponse::Signature {
                signature: vec![1, 2, 3]
            }
        );
        assert!(matches!(
            session_response(
                &provider_operation(),
                &session,
                BrokerRequest::SignSsh {
                    profile: "automation".into(),
                    purpose: SshOperationPurpose::GitSigning,
                    public_key_fingerprint:
                        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    payload: vec![1, 2, 3],
                },
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
            session_response(&provider_operation(), &session, request(), &SigningBackend).unwrap(),
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
            session_response(&provider_operation(), &session, request(), &SigningBackend).unwrap(),
            BrokerResponse::Denied { code, .. } if code == "resource_denied"
        ));
        session.authority.release_signing.as_mut().unwrap().products = vec!["dev-auth".into()];
        assert_eq!(
            session_response(&provider_operation(), &session, request(), &SigningBackend).unwrap(),
            BrokerResponse::Signature { signature: payload }
        );

        let crate_set = serde_jcs::to_vec(&serde_json::json!({
            "schema": "dev-tools-crate-set-v1",
            "authority": "dev-tools-shared-crates",
            "generation": 1,
            "source_commit": "a".repeat(40),
            "registry": "crates-io",
            "packages": {"dev-tools-command": {
                "version": "0.1.0",
                "length": 42,
                "sha256": "b".repeat(64),
            }}
        }))
        .unwrap();
        session.authority.release_signing.as_mut().unwrap().products =
            vec!["dev-tools-shared-crates".into()];
        let crate_request = BrokerRequest::SignReleaseManifest {
            profile: "release".into(),
            release_public_key: "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072"
                .into(),
            payload: crate_set.clone(),
        };
        assert_eq!(
            session_response(
                &provider_operation(),
                &session,
                crate_request,
                &SigningBackend
            )
            .unwrap(),
            BrokerResponse::Signature {
                signature: crate_set
            }
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
