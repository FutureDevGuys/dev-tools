//! Per-grant root coordinator. Credential broker authority is never involved.
use super::{
    adapter, custody,
    deadline::HardDeadline,
    policy::{self, ExactPlan},
    protocol::{self, Action, Envelope, ExecutionReply, Observation},
};
use anyhow::{bail, Context, Result};
use dev_tools_privilege_session::native_linux::{
    ChildStatus, ChildToken, KernelPeer, RetainedCgroupDomain, ValidatedCgroupBoundary,
};
use dev_tools_privilege_session::{Cleanup, LeaseState, StopReason};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_millis(20);
const CLEANUP: Duration = Duration::from_secs(10);
const STARTUP: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Controller {
    pub executable: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub cwd: Vec<u8>,
    pub environment: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub version: u32,
    pub session: String,
    pub approval: Vec<u8>,
    pub approval_sha256: String,
    pub approved_at_boot_ms: u64,
    pub login_session: String,
    pub controller: Controller,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChildPayload {
    Controller {
        owner_uid: u32,
        session: String,
        controller: Controller,
    },
    Operation {
        plan: ExactPlan,
        root: PathBuf,
        resources: Vec<custody::ResourceDescriptor>,
    },
}

pub fn session_directory(session: &str) -> Result<PathBuf> {
    protocol::token(session)?;
    Ok(Path::new(custody::RUNTIME_PATH).join(session))
}
pub fn socket_path(session: &str) -> Result<PathBuf> {
    Ok(session_directory(session)?.join("control.sock"))
}

pub fn serve(admission: Admission, bootstrap: &UnixStream) -> Result<Observation> {
    require_root()?;
    if admission.version != 1 {
        bail!("administrative admission version is unsupported");
    }
    protocol::token(&admission.session)?;
    let bootstrap_peer = crate::linux_admission::peer_evidence(bootstrap)?;
    let bootstrap_time = fs::metadata(format!("/proc/{}/ns/time", bootstrap_peer.pid))?;
    let native_time = fs::metadata("/proc/self/ns/time")?;
    if bootstrap_time.dev() != native_time.dev() || bootstrap_time.ino() != native_time.ino() {
        bail!("administrative approval clock namespace differs from the native guardian");
    }
    if bootstrap_peer.uid != 0 {
        bail!("administrative admission did not come from root infrastructure");
    }
    let _exclusion = crate::setup_transition::admit(crate::setup::InstallMode::Strong)?;
    let core_profile = super::platform::CoreDumpProfile::capture()?;
    let policy_bytes = custody::policy_bytes()?;
    let installation = custody::installation_identity()?;
    let approval = policy::verify_plan(
        &admission.approval,
        &admission.approval_sha256,
        &policy_bytes,
        &installation,
    )?;
    let owner =
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(approval.request.owner_uid))?
            .context("administrative owner account is absent")?;
    let login = super::login::LoginSession::retain(&admission.login_session, owner.uid.as_raw())?;
    let now = crate::linux_platform::boot_time_millis()?;
    if admission.approved_at_boot_ms > now {
        bail!("administrative approval clock is invalid");
    }
    let hard = crate::linux_platform::deadline_after_seconds(
        admission.approved_at_boot_ms,
        approval.request.hard_seconds,
    )?;
    if now >= hard {
        bail!("administrative approval expired before startup");
    }
    let mut backstop = HardDeadline::arm(hard)?;
    let path = guardian_cgroup(&admission.session)?;
    let boundary = ValidatedCgroupBoundary::open(&path)?;
    let mut controller = boundary.create_domain(std::ffi::OsStr::new("controller"))?;
    let directory = session_directory(&admission.session)?;
    verify_runtime_directory(&directory)?;
    let socket = socket_path(&admission.session)?;
    let listener = UnixListener::bind(&socket)?;
    let _socket_cleanup = SessionSocketGuard::retain(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    nix::unistd::chown(&socket, Some(owner.uid), Some(owner.gid))?;
    let child = controller.spawn_gated(
        child_command(&ChildPayload::Controller {
            owner_uid: owner.uid.as_raw(),
            session: admission.session.clone(),
            controller: admission.controller,
        })?,
        STARTUP,
    )?;
    let captured = approval
        .operations
        .iter()
        .flat_map(|(operation, definition)| {
            definition
                .plans
                .iter()
                .map(move |(plan, exact)| ((operation.clone(), plan.clone()), exact))
        })
        .map(|(key, exact)| {
            Ok((
                key,
                exact
                    .resources
                    .iter()
                    .map(|(name, r)| {
                        Ok((
                            name.clone(),
                            custody::HeldResource::open(Path::new(&r.path), owner.uid.as_raw())?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let main_executable = crate::setup::validate_installed_maintenance_helper()?;
    let mut watches = Vec::new();
    for path in [
        Path::new(custody::POLICY_PATH),
        Path::new(custody::HELPER_PATH),
        Path::new(custody::RECEIPT_PATH),
        Path::new(custody::POLKIT_PATH),
        main_executable.as_path(),
        Path::new("/usr/local/lib/dev-auth/install-v2.json"),
    ] {
        watches.push(custody::IdentityWatch::root(path, false)?);
    }
    watches.push(custody::IdentityWatch::root(
        Path::new("/usr/local/lib/dev-auth/active"),
        true,
    )?);
    for (operation_name, operation) in &approval.operations {
        if let Some(binding) = &operation.adapter {
            watches.push(custody::IdentityWatch::root(
                Path::new(&binding.receipt_path),
                false,
            )?);
        }
        for (plan_name, plan) in &operation.plans {
            validate_exact(
                plan,
                captured
                    .get(&(operation_name.clone(), plan_name.clone()))
                    .context("retained effect resources missing")?,
                operation.adapter.as_ref(),
            )?;
            watches.push(custody::IdentityWatch::root(
                Path::new(&plan.executable),
                false,
            )?);
        }
    }
    let mut next_login_check = Instant::now();
    let mut authority =
        adapter::create(&approval, &admission.session, admission.approved_at_boot_ms)?;
    if authority.poll(adapter::now()) != LeaseState::Active {
        bail!("administrative authority expired before controller release");
    }
    backstop.observe_next(
        authority
            .status()
            .next_deadline
            .context("administrative deadline is absent")?,
    )?;
    if !pidfd_alive(bootstrap_peer.peer_pidfd().as_fd().as_raw_fd())
        || core_profile.verify().is_err()
        || authority.poll(adapter::now()) != LeaseState::Active
    {
        bail!("administrative bootstrap or deadline was lost before controller release");
    }
    controller.release_child(child)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, incoming) = mpsc::sync_channel(16);
    let listener_worker = listen(listener, stop.clone(), sender)?;
    let mut current: Option<Running> = None;
    let mut controller_status = None;
    let mut prior_cleanup_failed = false;
    let outcome = (|| -> Result<()> {
        loop {
            authority.poll(adapter::now());
            if Instant::now() >= next_login_check {
                if login.verify().is_err() {
                    authority.stop(StopReason::AuthorityChanged);
                }
                next_login_check = Instant::now() + Duration::from_millis(250);
            }
            if let Some(deadline) = authority.status().next_deadline {
                backstop.observe_next(deadline)?;
            }
            if !pidfd_alive(bootstrap_peer.peer_pidfd().as_fd().as_raw_fd()) {
                authority.stop(StopReason::AuthorityChanged);
            }
            if core_profile.verify().is_err()
                || watches.iter().any(|watch| watch.verify().is_err())
                || captured.values().any(|resources| {
                    resources
                        .values()
                        .any(|resource| resource.verify().is_err())
                })
            {
                authority.stop(StopReason::AuthorityChanged);
            }
            if let ChildStatus::Exited(status) = controller.child_status(child)? {
                controller_status = Some(status);
                authority.shutdown(adapter::now());
            }
            if authority.status().state != LeaseState::Active {
                break;
            }
            if let Some(running) = current.as_mut() {
                let deadline = running
                    .started
                    .checked_add(Duration::from_secs(running.plan.timeout_seconds))
                    .context("administrative operation deadline overflow")?;
                if Instant::now() >= deadline || !running.peer.is_alive().unwrap_or(false) {
                    running.cancelled = true;
                }
                if running.output_failed.load(Ordering::Acquire) {
                    running.cancelled = true;
                }
                if running.cancelled
                    || matches!(
                        running.domain.child_status(running.child)?,
                        ChildStatus::Exited(_) | ChildStatus::SpawnFailed
                    )
                {
                    let mut finished = current
                        .take()
                        .context("administrative operation disappeared")?;
                    let status = match finished.domain.child_status(finished.child)? {
                        ChildStatus::Exited(s) => Some(s),
                        _ => None,
                    };
                    let cleanup = finished.domain.terminate(CLEANUP).and_then(|proof| {
                        if proof.had_prior_failure() {
                            return Err(dev_tools_privilege_session::native_linux::NativeError::CleanupNotComplete);
                        }
                        finished.domain.remove()
                    });
                    if cleanup.is_err() {
                        prior_cleanup_failed = true;
                    }
                    cleanup?;
                    let (stdout, stderr) = finished.finish_output()?;
                    authority.complete_operation(adapter::now(), finished.id)?;
                    if let Some(deadline) = authority.status().next_deadline {
                        backstop.observe_next(deadline)?;
                    }
                    let mut effect_error = None;
                    let mut invalid_report = false;
                    if let Some(request) = &finished.effect_request {
                        if !finished.cancelled {
                            match status.and_then(|s| s.code()).map(|code| {
                                super::receipt_install::verify_report(request, &stdout, code)
                            }) {
                                Some(Ok(report))
                                    if matches!(
                                        report.outcome.as_str(),
                                        "current" | "changed" | "unchanged"
                                    ) => {}
                                Some(Ok(_)) => {
                                    effect_error = Some("receipt_install_operation_failed")
                                }
                                _ => {
                                    effect_error = Some("receipt_install_result_unknown");
                                    // A native signal is an interrupted operation, not
                                    // an invented successful effect. Its approved
                                    // journal recovery may use a later grant call.
                                    invalid_report = status.and_then(|s| s.signal()).is_none();
                                }
                            }
                        }
                    }
                    let observation = observe(
                        &authority,
                        hard,
                        Effect {
                            outcome: if effect_error.is_some() {
                                "failed"
                            } else if finished.cancelled {
                                "cancelled"
                            } else {
                                "exited"
                            },
                            started: Some(true),
                            exit_code: status.and_then(|s| s.code()),
                            signal: status.and_then(|s| s.signal()),
                            cleanup_complete: true,
                            error: effect_error.or(if finished.cancelled {
                                Some("operation_cancelled")
                            } else {
                                None
                            }),
                        },
                    );
                    let _ = protocol::write(
                        &mut finished.stream,
                        &ExecutionReply {
                            observation,
                            stdout,
                            stderr,
                        },
                        protocol::CONTROL_BUDGET,
                    );
                    if invalid_report {
                        bail!("receipt installation result lost its trusted protocol");
                    }
                }
            }
            match incoming.recv_timeout(TICK) {
                Ok((mut stream, request)) => {
                    let peer = crate::linux_admission::peer_evidence(&stream)?;
                    if peer.uid != owner.uid.as_raw() || request.session != admission.session {
                        deny(&mut stream, &authority, hard, "peer_denied");
                        continue;
                    }
                    match request.action {
                        Action::Status {} => {
                            let _ = protocol::write(
                                &mut stream,
                                &observe(
                                    &authority,
                                    hard,
                                    Effect {
                                        outcome: "active",
                                        started: None,
                                        exit_code: None,
                                        signal: None,
                                        cleanup_complete: false,
                                        error: None,
                                    },
                                ),
                                protocol::CONTROL_BUDGET,
                            );
                        }
                        Action::Revoke {} => {
                            authority.stop(StopReason::Revoked);
                            let _ = protocol::write(
                                &mut stream,
                                &observe(
                                    &authority,
                                    hard,
                                    Effect {
                                        outcome: "stopping",
                                        started: None,
                                        exit_code: None,
                                        signal: None,
                                        cleanup_complete: false,
                                        error: None,
                                    },
                                ),
                                protocol::CONTROL_BUDGET,
                            );
                            break;
                        }
                        Action::Execute { name, plan } => {
                            if current.is_some() {
                                deny(&mut stream, &authority, hard, "busy");
                                continue;
                            }
                            let peer = match controller.authenticate_peer(
                                &stream,
                                owner.uid.as_raw(),
                                owner.gid.as_raw(),
                            ) {
                                Ok(peer) => peer,
                                Err(_) => {
                                    deny(&mut stream, &authority, hard, "peer_denied");
                                    continue;
                                }
                            };
                            let exact = match adapter::exact_plan(&approval, &name, &plan) {
                                Ok(plan) => plan.clone(),
                                Err(_) => {
                                    deny(&mut stream, &authority, hard, "operation_denied");
                                    continue;
                                }
                            };
                            let operation = approval
                                .operations
                                .get(&name)
                                .context("approved operation disappeared")?;
                            let executor_binding = operation.adapter.as_ref();
                            let effect_request =
                                if operation.protocol == super::receipt_install::PROTOCOL {
                                    Some(super::receipt_install::validate_plan(
                                        executor_binding,
                                        &exact,
                                    )?)
                                } else {
                                    None
                                };
                            let request = match adapter::request(
                                &authority,
                                &approval,
                                &request.request_id,
                                &name,
                                &plan,
                            ) {
                                Ok(r) => r,
                                Err(_) => {
                                    deny(&mut stream, &authority, hard, "request_denied");
                                    continue;
                                }
                            };
                            let retained = captured
                                .get(&(name.clone(), plan.clone()))
                                .context("administrative retained resource authority is absent")?;
                            let id =
                                match authority.admit_checked(adapter::now, request, |_, _, _| {
                                    validate_exact(&exact, retained, executor_binding).is_ok()
                                        && core_profile.verify().is_ok()
                                        && controller.revalidate_peer(&peer).is_ok()
                                        && pidfd_alive(
                                            bootstrap_peer.peer_pidfd().as_fd().as_raw_fd(),
                                        )
                                }) {
                                    Ok(id) => id,
                                    Err(_) => {
                                        deny(&mut stream, &authority, hard, "admission_denied");
                                        continue;
                                    }
                                };
                            // Admission is useful activity. Rearm before any potentially
                            // slow native gate preparation, never at the next loop tick.
                            if let Some(deadline) = authority.status().next_deadline {
                                backstop.observe_next(deadline)?;
                            }
                            let operation_name =
                                format!("operation-{}", authority.status().remaining_uses);
                            let mut domain =
                                boundary.create_domain(std::ffi::OsStr::new(&operation_name))?;
                            let root = directory.join(&operation_name);
                            fs::create_dir(&root)?;
                            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                            let mut descriptors = Vec::new();
                            let mut retained_fds = Vec::new();
                            for (name, resource) in retained {
                                let (descriptor, fd) = resource.transfer(name)?;
                                descriptors.push(descriptor);
                                retained_fds.push(fd);
                            }
                            let mut command = child_command_with_resources(
                                &ChildPayload::Operation {
                                    plan: exact.clone(),
                                    root,
                                    resources: descriptors,
                                },
                                retained_fds,
                            )?;
                            command
                                .stdin(Stdio::null())
                                .stdout(Stdio::piped())
                                .stderr(Stdio::piped());
                            let operation_child = domain.spawn_gated(command, STARTUP)?;
                            authority
                                .release_checked(
                                    adapter::now,
                                    id,
                                    |_, _, _| {
                                        validate_exact(&exact, retained, executor_binding).is_ok()
                                            && core_profile.verify().is_ok()
                                            && controller.revalidate_peer(&peer).is_ok()
                                        && pidfd_alive(bootstrap_peer.peer_pidfd().as_fd().as_raw_fd())
                                    },
                                    |_| {
                                        if controller.revalidate_peer(&peer).is_err() || !pidfd_alive(bootstrap_peer.peer_pidfd().as_fd().as_raw_fd()) {
                                            return Err(dev_tools_privilege_session::native_linux::NativeError::PeerExited);
                                        }
                                        domain.release_child(operation_child)
                                    },
                                )
                                .map_err(|_| {
                                    anyhow::anyhow!("administrative operation gate failed")
                                })?;
                            current = Some(Running::new(
                                domain,
                                operation_child,
                                id,
                                stream,
                                peer,
                                exact,
                                effect_request,
                            )?);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("administrative control listener stopped")
                }
            }
        }
        Ok(())
    })();
    if outcome.is_err() {
        authority.stop(StopReason::AuthorityChanged);
    }
    stop.store(true, Ordering::Release);
    let operation_cleanup = if let Some(mut operation) = current {
        operation
            .domain
            .terminate(CLEANUP)
            .and_then(|proof| {
                if proof.had_prior_failure() {
                    return Err(
                        dev_tools_privilege_session::native_linux::NativeError::CleanupNotComplete,
                    );
                }
                operation.domain.remove()
            })
            .map_err(anyhow::Error::from)
    } else {
        Ok(())
    };
    let controller_cleanup = controller
        .terminate(CLEANUP)
        .and_then(|proof| {
            if proof.had_prior_failure() {
                return Err(
                    dev_tools_privilege_session::native_linux::NativeError::CleanupNotComplete,
                );
            }
            controller.remove()
        })
        .map_err(anyhow::Error::from);
    let joined = listener_worker.join().is_ok();
    let cleaned =
        !prior_cleanup_failed && operation_cleanup.is_ok() && controller_cleanup.is_ok() && joined;
    authority.report_cleanup(if cleaned {
        Cleanup::Complete
    } else {
        Cleanup::Failed
    })?;
    if cleaned {
        fs::remove_file(&socket)?;
    }
    if !cleaned || outcome.is_err() {
        return Ok(observe(
            &authority,
            hard,
            Effect {
                outcome: "failed",
                started: Some(true),
                exit_code: Some(1),
                signal: None,
                cleanup_complete: cleaned,
                error: Some("session_cleanup_or_execution_failed"),
            },
        ));
    }
    Ok(observe(
        &authority,
        hard,
        Effect {
            outcome: if authority.status().state.is_clean_shutdown() {
                "completed"
            } else {
                "stopped"
            },
            started: Some(true),
            exit_code: controller_status.and_then(|s| s.code()),
            signal: controller_status.and_then(|s| s.signal()),
            cleanup_complete: true,
            error: None,
        },
    ))
}

/// Startup failures (including lost bootstrap after handoff) must not leave a
/// named control endpoint. SIGKILL paths are owned by the independent bootstrap.
struct SessionSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl SessionSocketGuard {
    fn retain(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}
impl Drop for SessionSocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == (self.device, self.inode))
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct Running {
    domain: RetainedCgroupDomain,
    child: ChildToken,
    id: dev_tools_privilege_session::RequestId,
    stream: UnixStream,
    peer: KernelPeer,
    plan: ExactPlan,
    effect_request: Option<super::receipt_install::Request>,
    started: Instant,
    cancelled: bool,
    output_failed: Arc<AtomicBool>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}
impl Running {
    fn new(
        mut domain: RetainedCgroupDomain,
        child: ChildToken,
        id: dev_tools_privilege_session::RequestId,
        stream: UnixStream,
        peer: KernelPeer,
        plan: ExactPlan,
        effect_request: Option<super::receipt_install::Request>,
    ) -> Result<Self> {
        let start = Instant::now();
        let streams = loop {
            if let Some(streams) = domain.take_child_streams(child)? {
                break streams;
            }
            if start.elapsed() > STARTUP {
                bail!("administrative output handoff timed out");
            }
            thread::sleep(TICK);
        };
        let failed = Arc::new(AtomicBool::new(false));
        let stdout = streams
            .stdout
            .map(|s| capture(s, plan.output_limit as usize, failed.clone()));
        let stderr = streams
            .stderr
            .map(|s| capture(s, plan.output_limit as usize, failed.clone()));
        Ok(Self {
            domain,
            child,
            id,
            stream,
            peer,
            plan,
            effect_request,
            started: Instant::now(),
            cancelled: false,
            output_failed: failed,
            stdout,
            stderr,
        })
    }
    fn finish_output(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let stdout = self
            .stdout
            .take()
            .map(|t| t.join())
            .transpose()
            .map_err(|_| anyhow::anyhow!("administrative output worker failed"))?
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .map(|t| t.join())
            .transpose()
            .map_err(|_| anyhow::anyhow!("administrative output worker failed"))?
            .unwrap_or_default();
        Ok((stdout, stderr))
    }
}
fn capture(
    mut stream: impl Read + Send + 'static,
    limit: usize,
    failed: Arc<AtomicBool>,
) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.len() + n > limit {
                        failed.store(true, Ordering::Release);
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    failed.store(true, Ordering::Release);
                    break;
                }
            }
        }
        out
    })
}
fn listen(
    listener: UnixListener,
    stop: Arc<AtomicBool>,
    sender: mpsc::SyncSender<(UnixStream, Envelope)>,
) -> Result<JoinHandle<()>> {
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    Ok(thread::spawn(move || {
        let mut workers = Vec::new();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if active.load(Ordering::Acquire) >= 16 {
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let sender = sender.clone();
                    let active = active.clone();
                    workers.push(thread::spawn(move || {
                        if let Ok(bytes) = protocol::read(&mut stream, protocol::CONTROL_BUDGET) {
                            if let Ok(request) = protocol::parse_request(&bytes) {
                                let _ = sender.try_send((stream, request));
                            }
                        }
                        active.fetch_sub(1, Ordering::AcqRel);
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(TICK),
                Err(_) => break,
            }
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
    }))
}
fn validate_exact(
    plan: &ExactPlan,
    resources: &BTreeMap<String, custody::HeldResource>,
    executor: Option<&super::receipt_install::ExecutorBinding>,
) -> Result<()> {
    if let Some(binding) = executor {
        return super::receipt_install::verify_native(binding, plan, resources);
    }
    let _ = custody::held_root_executable(Path::new(&plan.executable), &plan.executable_sha256)?;
    for resource in resources.values() {
        resource.verify()?;
    }
    Ok(())
}
struct Effect<'a> {
    outcome: &'a str,
    started: Option<bool>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    cleanup_complete: bool,
    error: Option<&'a str>,
}
fn observe(authority: &adapter::Authority, hard: u64, effect: Effect<'_>) -> Observation {
    Observation {
        version: 1,
        outcome: effect.outcome.into(),
        started: effect.started,
        exit_code: effect.exit_code,
        signal: effect.signal,
        remaining_uses: authority.status().remaining_uses,
        hard_deadline_boot_ms: hard,
        cleanup_complete: effect.cleanup_complete,
        error_kind: effect.error.map(str::to_owned),
    }
}

fn deny(stream: &mut UnixStream, authority: &adapter::Authority, hard: u64, error: &str) {
    let _ = protocol::write(
        stream,
        &ExecutionReply {
            observation: observe(
                authority,
                hard,
                Effect {
                    outcome: "denied",
                    started: Some(false),
                    exit_code: Some(4),
                    signal: None,
                    cleanup_complete: false,
                    error: Some(error),
                },
            ),
            stdout: vec![],
            stderr: vec![],
        },
        protocol::CONTROL_BUDGET,
    );
}
fn require_root() -> Result<()> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        bail!("administrative infrastructure requires native root");
    }
    Ok(())
}
fn guardian_cgroup(session: &str) -> Result<PathBuf> {
    protocol::token(session)?;
    let bytes = fs::read_to_string("/proc/self/cgroup")?;
    if bytes.len() > 4096 {
        bail!("administrative cgroup observation exceeds bounds");
    }
    let wanted = format!("0::/system.slice/dev-auth-maintenance-{session}.service");
    if bytes
        .lines()
        .filter(|l| l.starts_with("0::"))
        .collect::<Vec<_>>()
        != [wanted.as_str()]
    {
        bail!("administrative coordinator is outside its native guardian");
    }
    Ok(Path::new("/sys/fs/cgroup/system.slice")
        .join(format!("dev-auth-maintenance-{session}.service")))
}
fn verify_runtime_directory(path: &Path) -> Result<()> {
    custody::validate_parents(&path.join("leaf"), 0, false)?;
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7777 != 0o711 {
        bail!("administrative runtime custody is invalid");
    }
    Ok(())
}

pub fn child_command(payload: &ChildPayload) -> Result<Command> {
    child_command_with_resources(payload, Vec::new())
}
fn child_command_with_resources(
    payload: &ChildPayload,
    resources: Vec<OwnedFd>,
) -> Result<Command> {
    let bytes = policy::canonical(payload)?;
    let mut file = memory_file(&bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let fd = file.as_raw_fd();
    let mut command = Command::new(custody::HELPER_PATH);
    command
        .arg("child-v1")
        .arg("--payload-fd")
        .arg(fd.to_string())
        .env_clear();
    // SAFETY: captured File retains its fd until the gated spawn completes. Only
    // the exact sealed public capsule is deliberately inherited by this helper.
    unsafe {
        command.pre_exec(move || {
            let _keep = &file;
            for resource in &resources {
                if nix::libc::fcntl(resource.as_raw_fd(), nix::libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}
fn memory_file(bytes: &[u8]) -> Result<File> {
    let name = CString::new("dev-auth-privilege-capsule")?;
    let fd = unsafe {
        nix::libc::memfd_create(
            name.as_ptr(),
            nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create administrative capsule");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let seals = nix::libc::F_SEAL_SEAL
        | nix::libc::F_SEAL_SHRINK
        | nix::libc::F_SEAL_GROW
        | nix::libc::F_SEAL_WRITE;
    if unsafe { nix::libc::fcntl(fd, nix::libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error()).context("seal administrative capsule");
    }
    Ok(file)
}
pub fn child(fd: i32) -> Result<i32> {
    require_root()?;
    if fd < 3 {
        bail!("administrative capsule descriptor is invalid");
    }
    let seals = nix::libc::F_SEAL_SEAL
        | nix::libc::F_SEAL_SHRINK
        | nix::libc::F_SEAL_GROW
        | nix::libc::F_SEAL_WRITE;
    if unsafe { nix::libc::fcntl(fd, nix::libc::F_GET_SEALS) } != seals {
        bail!("administrative capsule is not sealed");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    (&mut file)
        .take(policy::DOCUMENT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    drop(file);
    let payload: ChildPayload = policy::parse(&bytes)?;
    match payload {
        ChildPayload::Operation {
            plan,
            root,
            resources,
        } => super::sandbox::execute(&plan, &root, resources),
        ChildPayload::Controller {
            owner_uid,
            session,
            controller,
        } => {
            protocol::token(&session)?;
            let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
                .context("native controller owner is absent")?;
            if owner_uid == 0 {
                bail!("administrative controller must remain non-root");
            }
            let name = CString::new(owner.name.clone())?;
            let groups = nix::unistd::getgrouplist(&name, owner.gid)?;
            nix::unistd::setgroups(&groups)?;
            nix::unistd::setgid(owner.gid)?;
            nix::unistd::setuid(owner.uid)?;
            if unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("restrict controller privilege");
            }
            let mut command = Command::new(OsString::from_vec(controller.executable));
            command
                .args(controller.arguments.into_iter().map(OsString::from_vec))
                .current_dir(OsString::from_vec(controller.cwd))
                .env_clear()
                .envs(controller.environment)
                .env("HOME", owner.dir)
                .env("USER", &owner.name)
                .env("LOGNAME", owner.name)
                .env("DEV_AUTH_PRIVILEGE_SESSION", session);
            Err(command.exec()).context("start approved native controller")
        }
    }
}

fn pidfd_alive(fd: i32) -> bool {
    let mut poll = nix::libc::pollfd {
        fd,
        events: nix::libc::POLLIN,
        revents: 0,
    };
    unsafe { nix::libc::poll(&mut poll, 1, 0) == 0 }
}
