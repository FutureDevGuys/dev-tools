use super::model::{Envelope, FRAME_LIMIT, WIRE_SCHEMA};
use super::native::{self, Caller};
use super::policy::{Account, NativeScope, Policy};
use super::{
    Authority, ControlRequest, ControlResult, Failure, Grant, GrantRequest, GrantScope, GrantState,
};
use dev_tools_privilege_session::linux::{boot_time, ExecutionBoundary};
use dev_tools_privilege_session::Constraint;
use dev_tools_privilege_session::{
    Cleanup, GrantId, GrantRegistry, LeaseState, SessionError, StopReason,
};
use nix::sys::socket::{self, AddressFamily, Backlog, MsgFlags, SockFlag, SockType, UnixAddr};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

mod sudo_bridge;

const MAX_GRANTS: usize = 128;
const MAX_CONNECTIONS: usize = 32;
const MAX_EXECUTIONS: usize = 64;

pub struct Configuration {
    pub policy: PathBuf,
    pub runtime: PathBuf,
}

struct Metadata {
    request: GrantRequest,
    scope: NativeScope,
    boundary: ExecutionBoundary,
    workload: Option<File>,
    terminal_since: Option<Duration>,
    launch_owner: Option<LaunchOwner>,
}

/// A pending launch is owned by one retained native installed supervisor, not
/// a submitted PID, environment selector or serialized proof flag.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LaunchPhase {
    Pending,
    DirectAwaitingRelease,
    BootstrapAwaitingRelease,
}

struct LaunchOwner {
    pid: u32,
    pidfd: OwnedFd,
    scope: NativeScope,
    image: File,
    native_cgroup: PathBuf,
    phase: LaunchPhase,
    release_deadline: Option<Duration>,
}

impl LaunchOwner {
    fn retain(caller: &Caller) -> Result<Self, Failure> {
        if caller.workload.is_none() || !caller.still_present() {
            return Err(Failure::AuthorityDenied);
        }
        let image = File::open(format!("/proc/{}/exe", caller.peer.pid))
            .map_err(|_| Failure::AuthorityDenied)?;
        let installed = File::open("/proc/self/exe").map_err(|_| Failure::NativeUnavailable)?;
        let stamp = image.metadata().map_err(|_| Failure::AuthorityDenied)?;
        if stamp.uid() != 0
            || stamp.mode() & 0o022 != 0
            || !stamp.is_file()
            || !native::same_file(&image, &installed)?
        {
            return Err(Failure::AuthorityDenied);
        }
        Ok(Self {
            pid: caller.peer.pid,
            pidfd: native::clone_fd(caller.peer.peer_pidfd())?,
            scope: caller.scope.clone(),
            image,
            native_cgroup: caller.peer.unified_cgroup.clone(),
            phase: LaunchPhase::Pending,
            release_deadline: None,
        })
    }

    fn present(&self) -> bool {
        native::alive(&self.pidfd)
            && crate::linux_admission::read_unified_cgroup(self.pid)
                .is_ok_and(|path| path == self.native_cgroup)
            && File::open(format!("/proc/{}/exe", self.pid))
                .is_ok_and(|image| native::same_file(&image, &self.image).unwrap_or(false))
    }

    fn available(&self) -> bool {
        self.phase != LaunchPhase::Pending
            && self.present()
            && self
                .release_deadline
                .is_some_and(|deadline| now().is_ok_and(|observed| observed < deadline))
    }

    fn revocation_reason(&self) -> Option<StopReason> {
        (!self.present()
            || self
                .release_deadline
                .is_some_and(|deadline| !now().is_ok_and(|observed| observed < deadline)))
        .then_some(StopReason::WorkloadEnded)
    }

    fn matches(&self, caller: &Caller) -> bool {
        caller.peer.pid == self.pid
            && caller.scope == self.scope
            && self.present()
            && caller.still_present()
            && File::open(format!("/proc/{}/exe", caller.peer.pid))
                .is_ok_and(|image| native::same_file(&image, &self.image).unwrap_or(false))
    }
}

struct Job {
    grant: GrantId,
    boundary: ExecutionBoundary,
    preparing: bool,
    leader_done: bool,
    external_leader: Option<OwnedFd>,
    external_complete: bool,
    origin: NativeScope,
    relay: RelayAdmission,
    captured: Option<CapturedJob>,
}

/// State owns both direct children before the spawn task returns, including
/// when its connection future is cancelled. Native polling under this mutex
/// is their sole waiter; a failed bounded join retains this ownership.
struct CapturedJob {
    counters: super::output::Counters,
    worker: Option<std::process::Child>,
    relay: Option<std::process::Child>,
    worker_status: Option<std::process::ExitStatus>,
    relay_status: Option<std::process::ExitStatus>,
    spawn_finished: bool,
    spawn_failed: bool,
    wait_failed: bool,
    cleanup_failed: bool,
    stopped: Option<nix::sys::signal::Signal>,
    published: bool,
    drain: super::output::DrainSettlement,
    drain_failed: bool,
    connection: OwnedFd,
    boundary_removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayAdmission {
    Ordinary,
    Preparing,
    Ready(u32),
    Claimed,
}

impl RelayAdmission {
    fn may_claim(self, pid: u32) -> bool {
        self == Self::Ready(pid)
    }
    fn claim(&mut self, pid: u32) -> Result<(), Failure> {
        if !self.may_claim(pid) {
            return Err(Failure::AuthorityDenied);
        }
        *self = Self::Claimed;
        Ok(())
    }
}

struct State {
    registry: GrantRegistry<NativeScope, Authority>,
    metadata: BTreeMap<GrantId, Metadata>,
    selected: BTreeMap<NativeScope, GrantId>,
    jobs: BTreeMap<GrantId, Job>,
    pending_relays: BTreeMap<u32, PendingRelay>,
    stopping: bool,
}

struct PendingRelay {
    caller: Caller,
    grant: GrantId,
    expires: Duration,
}

struct Service {
    policy: Policy,
    policy_file: File,
    policy_stamp: FileStamp,
    policy_path: PathBuf,
    parent: File,
    runtime: PathBuf,
    coordinator: OwnedFd,
    sudo_file: File,
    sudo_stamp: FileStamp,
    product_file: File,
    state: Mutex<State>,
    pending: std::sync::Mutex<BTreeSet<Account>>,
}

fn setup_admission(
    service: &Service,
) -> Result<Option<dev_tools_installation::InstallationLock>, Failure> {
    // Explicit root-owned isolated native fixtures use their own runtime and
    // cannot acquire, create or read the real installation's setup state.
    if service.runtime.join("control.sock") != Path::new(super::SYSTEM_SOCKET) {
        return Ok(None);
    }
    crate::setup_transition::try_grant_admission()
        .map_err(|_| Failure::AuthorityDenied)?
        .map(Some)
        .ok_or(Failure::Busy)
}

/// The production daemon has one native approval backend. The root-only native
/// acceptance harness is separate; there is no command-line approval bypass.
pub fn serve(configuration: Configuration) -> Result<(), Failure> {
    if !nix::unistd::Uid::effective().is_root() || !nix::unistd::Uid::current().is_root() {
        return Err(Failure::AuthorityDenied);
    }
    let executable = std::env::current_exe().map_err(|_| Failure::NativeUnavailable)?;
    let product_file = root_file(&executable, false)?;
    crate::linux_platform::IdentityUserNamespace::from_current_process()
        .map_err(|_| Failure::NativeUnavailable)?;
    let current_namespace =
        File::open("/proc/self/ns/user").map_err(|_| Failure::NativeUnavailable)?;
    let init_namespace = File::open("/proc/1/ns/user").map_err(|_| Failure::NativeUnavailable)?;
    if !native::same_file(&current_namespace, &init_namespace)? {
        return Err(Failure::NativeUnavailable);
    }
    let runtime_directory = root_file(&configuration.runtime, true)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(configuration.runtime.join("daemon.lock"))
        .map_err(|_| Failure::AuthorityDenied)?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| Failure::Busy)?;
    let policy_file = root_file(&configuration.policy, false)?;
    let policy_stamp = FileStamp::of(&policy_file)?;
    let mut bytes = Vec::new();
    policy_file
        .try_clone()
        .map_err(|_| Failure::NativeUnavailable)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::NativeUnavailable)?;
    if bytes.len() > 1024 * 1024 {
        return Err(Failure::InvalidRequest);
    }
    let policy: Policy = serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidRequest)?;
    policy.validate()?;
    let sudo_file = root_file(Path::new(&policy.sudo_program), false)?;
    let sudo_stamp = FileStamp::of(&sudo_file)?;
    if FileStamp::of(&policy_file)? != policy_stamp {
        return Err(Failure::AuthorityDenied);
    }
    let parent_path = own_service_cgroup()?;
    let parent = root_file(&parent_path, true)?;
    // SAFETY: pidfd_open returns a new owned descriptor or a negative error;
    // flags are zero and this process remains live during construction.
    let descriptor =
        unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, std::process::id(), 0) };
    if descriptor < 0 {
        return Err(Failure::NativeUnavailable);
    }
    let coordinator = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(8)
        .build()
        .map_err(|_| Failure::NativeUnavailable)?;
    runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), verify_service_unit(&parent_path)).await
        })
        .map_err(|_| Failure::NativeUnavailable)??;
    // Systemd owns crash cleanup of the entire unit. Stale routing records are
    // denial state only; they never restore a memory-only grant. Do not accept
    // requests until all owned remnants are gone and their cleanup is proven.
    recover_cgroups(&parent)?;
    let selected = load_markers(&configuration.runtime)?;
    let listener = create_listener(&configuration.runtime.join("control.sock"))?;
    let sudo_listener = create_listener(&configuration.runtime.join("sudo.sock"))?;
    let service = Arc::new(Service {
        policy,
        policy_file,
        policy_stamp,
        policy_path: configuration.policy,
        parent,
        runtime: configuration.runtime,
        coordinator,
        sudo_file,
        sudo_stamp,
        product_file,
        state: Mutex::new(State {
            registry: GrantRegistry::new(MAX_GRANTS).map_err(|_| Failure::RuntimeFailure)?,
            metadata: BTreeMap::new(),
            selected,
            jobs: BTreeMap::new(),
            pending_relays: BTreeMap::new(),
            stopping: false,
        }),
        pending: std::sync::Mutex::new(BTreeSet::new()),
    });
    let result = runtime.block_on(run(service, listener, sudo_listener));
    drop(runtime_directory);
    drop(lock);
    result
}

fn create_listener(socket_path: &Path) -> Result<OwnedFd, Failure> {
    if let Ok(metadata) = std::fs::symlink_metadata(socket_path) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err(Failure::AuthorityDenied);
        }
        // The retained root runtime and exclusive daemon lock establish the
        // stale endpoint's ownership; no live compliant daemon can own it.
        std::fs::remove_file(socket_path).map_err(|_| Failure::RuntimeFailure)?;
    }
    let listener = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|_| Failure::NativeUnavailable)?;
    socket::bind(
        listener.as_raw_fd(),
        &UnixAddr::new(socket_path).map_err(|_| Failure::InvalidRequest)?,
    )
    .map_err(|_| Failure::RuntimeFailure)?;
    socket::listen(
        &listener,
        Backlog::new(MAX_CONNECTIONS as i32).map_err(|_| Failure::InvalidRequest)?,
    )
    .map_err(|_| Failure::RuntimeFailure)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
        .map_err(|_| Failure::RuntimeFailure)?;
    Ok(listener)
}

async fn run(
    service: Arc<Service>,
    listener: OwnedFd,
    sudo_listener: OwnedFd,
) -> Result<(), Failure> {
    let listener = AsyncFd::new(listener).map_err(|_| Failure::NativeUnavailable)?;
    let sudo_listener = AsyncFd::new(sudo_listener).map_err(|_| Failure::NativeUnavailable)?;
    let timer = nix::sys::timerfd::TimerFd::new(
        nix::sys::timerfd::ClockId::CLOCK_BOOTTIME,
        nix::sys::timerfd::TimerFlags::TFD_CLOEXEC | nix::sys::timerfd::TimerFlags::TFD_NONBLOCK,
    )
    .map_err(|_| Failure::NativeUnavailable)?;
    use nix::sys::time::TimeValLike;
    timer
        .set(
            nix::sys::timer::Expiration::Interval(nix::sys::time::TimeSpec::milliseconds(100)),
            nix::sys::timerfd::TimerSetTimeFlags::empty(),
        )
        .map_err(|_| Failure::NativeUnavailable)?;
    let timer = AsyncFd::new(OwnedFd::from(timer)).map_err(|_| Failure::NativeUnavailable)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| Failure::NativeUnavailable)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| Failure::NativeUnavailable)?;
    let mut connections = tokio::task::JoinSet::new();
    let mut login_tick = 0_u32;
    let mut login_check: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        tokio::select! {
            biased;
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            readiness = timer.readable() => {
                let mut readiness = readiness.map_err(|_| Failure::NativeUnavailable)?;
                let mut bytes = [0_u8; 8];
                let _ = readiness.try_io(|fd| nix::unistd::read(fd.get_ref(), &mut bytes).map_err(io::Error::from));
                reap(&service).await?;
                login_tick += 1;
                if login_tick >= 10 {
                    login_tick = 0;
                    if login_check.as_ref().is_none_or(tokio::task::JoinHandle::is_finished) {
                        if let Some(finished) = login_check.take() {
                            if finished.await.is_err() { break; }
                        }
                        let service = Arc::clone(&service);
                        login_check = Some(tokio::spawn(async move { check_logins(&service).await; }));
                    }
                }
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) { break; }
            }
            readiness = listener.readable(), if connections.len() < MAX_CONNECTIONS => {
                let mut readiness = readiness.map_err(|_| Failure::NativeUnavailable)?;
                let accepted = readiness.try_io(|fd| {
                    socket::accept4(fd.get_ref().as_raw_fd(), SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK)
                        .map_err(io::Error::from)
                });
                if let Ok(Ok(descriptor)) = accepted {
                    // SAFETY: successful accept4 returns a newly owned descriptor.
                    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                    let service = Arc::clone(&service);
                    connections.spawn(async move { let _ = connection(service, descriptor).await; });
                }
            }
            readiness = sudo_listener.readable(), if connections.len() < MAX_CONNECTIONS => {
                let mut readiness = readiness.map_err(|_| Failure::NativeUnavailable)?;
                let accepted = readiness.try_io(|fd| socket::accept4(fd.get_ref().as_raw_fd(), SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK).map_err(io::Error::from));
                if let Ok(Ok(descriptor)) = accepted {
                    // SAFETY: successful accept4 returns a newly owned FD.
                    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                    let service = Arc::clone(&service);
                    connections.spawn(async move { let _ = sudo_bridge::connection(service, descriptor).await; });
                }
            }
        }
    }
    {
        let mut state = service.state.lock().await;
        state.stopping = true;
        state.registry.stop_all(StopReason::BrokerShutdown, now()?);
    }
    for _ in 0..50 {
        reap(&service).await?;
        if service
            .state
            .lock()
            .await
            .registry
            .iter()
            .all(|grant| grant.lifetime.state().is_terminal())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(login_check) = login_check {
        login_check.abort();
        let _ = login_check.await;
    }
    if service
        .state
        .lock()
        .await
        .registry
        .iter()
        .any(|grant| !grant.lifetime.state().is_terminal())
    {
        return Err(Failure::CleanupFailed);
    }
    Ok(())
}

async fn connection(service: Arc<Service>, descriptor: OwnedFd) -> Result<(), Failure> {
    socket::setsockopt(&descriptor, socket::sockopt::PassCred, &true)
        .map_err(|_| Failure::NativeUnavailable)?;
    let caller = Caller::capture(&descriptor)?;
    let descriptor = AsyncFd::new(descriptor).map_err(|_| Failure::NativeUnavailable)?;
    send_packet(&descriptor, super::transport::HELLO).await?;
    let (envelope, streams) = tokio::time::timeout(
        Duration::from_secs(10),
        receive_packet(&descriptor, &caller),
    )
    .await
    .map_err(|_| Failure::ProtocolViolation)??;
    let operation = envelope.request.operation();
    let response = if envelope.schema != WIRE_SCHEMA
        || envelope.request.validate().is_err()
        || !request_descriptors_valid(&envelope.request, streams.len())
    {
        ControlResult::failure(operation, Failure::InvalidRequest, Some(false))
    } else {
        dispatch(
            &service,
            caller,
            envelope.request,
            streams,
            descriptor.get_ref(),
        )
        .await
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| Failure::RuntimeFailure)?;
    send_packet(&descriptor, &bytes).await
}

fn request_descriptors_valid(request: &ControlRequest, count: usize) -> bool {
    match request {
        ControlRequest::ActivateLaunch {
            bootstrap: true, ..
        } => count == 3,
        ControlRequest::ActivateLaunch {
            bootstrap: false, ..
        } => count == 0,
        _ if request.execution_terminal().is_some() => count == 4,
        _ => count == 0,
    }
}

async fn dispatch(
    service: &Arc<Service>,
    mut caller: Caller,
    request: ControlRequest,
    streams: Vec<OwnedFd>,
    connection: &OwnedFd,
) -> ControlResult {
    let operation = request.operation();
    if let Err(failure) = normalize_execution_scope(service, &mut caller).await {
        return ControlResult::failure(operation, failure, Some(false));
    }
    if !caller.still_present() {
        return ControlResult::failure(operation, Failure::AuthorityDenied, Some(false));
    }
    if let Err(failure) = sweep_abandoned_launches(service).await {
        return ControlResult::failure(operation, failure, Some(false));
    }
    if !policy_unchanged(service) {
        let mut state = service.state.lock().await;
        if let Ok(now) = now() {
            state.registry.stop_all(StopReason::AuthorityChanged, now);
        }
        for metadata in state.metadata.values_mut() {
            let _ = metadata.boundary.stop();
        }
        return ControlResult::failure(operation, Failure::AuthorityDenied, Some(false));
    }
    let mut progress = Progress::default();
    let result = match request {
        ControlRequest::Request { request } => {
            issue(service, &caller, request, &mut progress, connection, false).await
        }
        ControlRequest::LaunchRequest { request } => {
            issue(service, &caller, request, &mut progress, connection, true).await
        }
        ControlRequest::ActivateLaunch { grant, bootstrap } => {
            activate_launch(
                service,
                &caller,
                &grant,
                bootstrap.then_some(streams),
                &mut progress,
            )
            .await
        }
        ControlRequest::CommitLaunch { grant } => {
            commit_launch(service, &caller, &grant, &mut progress).await
        }
        ControlRequest::Status => observe(service, &caller, None).await,
        ControlRequest::Inspect { grant } => observe(service, &caller, Some(&grant)).await,
        ControlRequest::Revoke { grant } => {
            revoke(service, &caller, Some(&grant), false, &mut progress).await
        }
        ControlRequest::Leave => revoke(service, &caller, None, true, &mut progress).await,
        ControlRequest::Delegate { grant, request } => {
            delegate(service, &caller, &grant, request, &mut progress).await
        }
        ControlRequest::Exec { grant, execution } => {
            execute(
                service,
                &caller,
                grant.as_deref(),
                RequestedExecution::Command(execution),
                streams,
                connection,
                &mut progress,
            )
            .await
        }
        ControlRequest::RunPlan {
            grant,
            authority,
            terminal,
        } => {
            execute(
                service,
                &caller,
                grant.as_deref(),
                RequestedExecution::Plan {
                    authority,
                    terminal,
                },
                streams,
                connection,
                &mut progress,
            )
            .await
        }
        ControlRequest::SudoRelay { grant, execution } => {
            execute(
                service,
                &caller,
                Some(&grant),
                RequestedExecution::SudoRelay(execution),
                streams,
                connection,
                &mut progress,
            )
            .await
        }
    };
    progress.finish(operation, result)
}

async fn normalize_execution_scope(service: &Service, caller: &mut Caller) -> Result<(), Failure> {
    let state = service.state.lock().await;
    let directory =
        File::open(&caller.peer.unified_cgroup).map_err(|_| Failure::AuthorityDenied)?;
    for job in state.jobs.values() {
        if native::same_file(&directory, job.boundary.directory())? {
            if job.origin.account != caller.scope.account {
                return Err(Failure::AuthorityDenied);
            }
            caller.scope = job.origin.clone();
            caller.workload = state
                .metadata
                .get(&job.grant)
                .ok_or(Failure::NoGrant)?
                .workload
                .as_ref()
                .map(File::try_clone)
                .transpose()
                .map_err(|_| Failure::NativeUnavailable)?;
            break;
        }
    }
    Ok(())
}

/// Observation failure cannot erase an already established grant, use charge,
/// routing change or teardown. No retry is inferred from a failure response.
struct Progress(Option<bool>);

impl Default for Progress {
    fn default() -> Self {
        Self(Some(false))
    }
}

impl Progress {
    fn entered(&mut self) {
        if self.0 != Some(true) {
            self.0 = None;
        }
    }
    fn changed(&mut self) {
        self.0 = Some(true);
    }
    fn finish(self, operation: &str, result: Result<ControlResult, Failure>) -> ControlResult {
        result.unwrap_or_else(|failure| ControlResult::failure(operation, failure, self.0))
    }
}

async fn issue(
    service: &Service,
    caller: &Caller,
    mut request: GrantRequest,
    progress: &mut Progress,
    control: &OwnedFd,
    pending_launch: bool,
) -> Result<ControlResult, Failure> {
    drop(setup_admission(service)?);
    let launch_owner = pending_launch
        .then(|| LaunchOwner::retain(caller))
        .transpose()?;
    let limits = service
        .policy
        .approve_limits(&caller.scope.account, &request)?;
    let scope = requested_scope(caller, request.scope)?;
    request.idle_seconds = effective_idle(&service.policy, &scope.account, &request)?;
    if request.scope == GrantScope::User {
        let Account::Unix { uid } = &scope.account else {
            return Err(Failure::AuthorityDenied);
        };
        if !super::approval::account_has_login(*uid).await? {
            return Err(Failure::AuthorityDenied);
        }
    }
    let id = new_id()?;
    let pending = {
        let state = service.state.lock().await;
        let mut pending = service
            .pending
            .lock()
            .map_err(|_| Failure::RuntimeFailure)?;
        if state.stopping
            || pending.len() >= 4
            || state.registry.iter().count() + pending.len() >= MAX_GRANTS
            || !pending.insert(scope.account.clone())
        {
            return Err(Failure::Busy);
        }
        PendingApproval {
            pending: &service.pending,
            account: scope.account.clone(),
        }
    };
    let approval = super::approval::approve(caller, &request, &format!("{id:032x}"), control).await;
    let mut state = service.state.lock().await;
    drop(pending);
    approval?;
    let _setup = setup_admission(service)?;
    if state.stopping
        || !caller.still_present()
        || !policy_unchanged(service)
        || launch_owner
            .as_ref()
            .is_some_and(|owner| !owner.matches(caller))
    {
        return Err(Failure::AuthorityDenied);
    }
    let now = now()?;
    let deadline = now
        .checked_add(limits.hard_timeout())
        .ok_or(Failure::InvalidRequest)?;
    let boundary =
        ExecutionBoundary::create(&service.parent, &format!("grant-{id:032x}"), deadline)
            .map_err(|_| Failure::NativeUnavailable)?;
    let workload = if scope.workload.is_some() {
        caller
            .workload
            .as_ref()
            .map(File::try_clone)
            .transpose()
            .map_err(|_| Failure::RuntimeFailure)?
    } else {
        None
    };
    state
        .registry
        .issue(
            id,
            scope.clone(),
            request.authority.clone(),
            limits,
            request.uses.and_then(NonZeroU64::new),
            now,
        )
        .map_err(session_failure)?;
    progress.changed();
    state.metadata.insert(
        id,
        Metadata {
            request,
            scope: scope.clone(),
            boundary,
            workload,
            terminal_since: None,
            launch_owner,
        },
    );
    // The registry and its cleanup owner exist before publication. If routing
    // publication fails, no unowned active grant survives the failed request.
    if !pending_launch {
        if let Err(failure) = write_marker(service, &scope, id) {
            state
                .registry
                .stop(id, StopReason::Revoked, now)
                .map_err(session_failure)?;
            if let Some(metadata) = state.metadata.get_mut(&id) {
                let _ = metadata.boundary.stop();
            }
            return Err(failure);
        }
        state.selected.insert(scope, id);
    }
    let mut response = ControlResult::success("request", true);
    response.grant = Some(snapshot(&state, id, now)?);
    Ok(response)
}

struct VerifiedBootstrap {
    owner: crate::supervisor::startup_proof::RootSpawnOwner,
    proof: crate::supervisor::startup_proof::Proof,
    socket: OwnedFd,
    release: OwnedFd,
}

async fn activate_launch(
    service: &Service,
    caller: &Caller,
    submitted: &str,
    bootstrap: Option<Vec<OwnedFd>>,
    progress: &mut Progress,
) -> Result<ControlResult, Failure> {
    let _setup = setup_admission(service)?;
    let id = parse_id(submitted)?;
    let mut bootstrap = if let Some(mut descriptors) = bootstrap {
        if descriptors.len() != 3 {
            return Err(Failure::InvalidRequest);
        }
        let release = descriptors.pop().ok_or(Failure::InvalidRequest)?;
        crate::supervisor::startup_proof::validate_release_writer(&release)
            .map_err(|_| Failure::InvalidRequest)?;
        let spawn = descriptors.pop().ok_or(Failure::InvalidRequest)?;
        let socket = descriptors.pop().ok_or(Failure::InvalidRequest)?;
        let state = service.state.lock().await;
        let owner = state
            .metadata
            .get(&id)
            .and_then(|metadata| metadata.launch_owner.as_ref())
            .filter(|owner| owner.phase == LaunchPhase::Pending && owner.matches(caller))
            .ok_or(Failure::AuthorityDenied)?;
        let authority = crate::supervisor::startup_proof::SpawnAuthority {
            parent_pid: caller.peer.pid,
            parent_pidfd: native::clone_fd(caller.peer.peer_pidfd())?,
            image: owner
                .image
                .try_clone()
                .map_err(|_| Failure::NativeUnavailable)?,
            cgroup: caller.peer.unified_cgroup.clone(),
            uid: caller.peer.uid,
            gid: caller.peer.gid,
        };
        drop(state);
        Some(
            tokio::task::spawn_blocking(move || {
                let owner =
                    crate::supervisor::startup_proof::RootSpawnOwner::from_authenticated_spawn(
                        spawn, authority,
                    )?;
                let proof = crate::supervisor::startup_proof::await_ready(&socket, &owner)?;
                Ok::<_, anyhow::Error>(VerifiedBootstrap {
                    owner,
                    proof,
                    socket,
                    release,
                })
            })
            .await
            .map_err(|_| Failure::NativeUnavailable)?
            .map_err(|_| Failure::AuthorityDenied)?,
        )
    } else {
        None
    };
    {
        let observed = now()?;
        let mut state = service.state.lock().await;
        state.registry.poll(observed);
        require_launch_state(service, &state, id, caller, LaunchPhase::Pending)?;
        if let Some(bootstrap) = &bootstrap {
            bootstrap
                .proof
                .recheck(&bootstrap.owner)
                .map_err(|_| Failure::AuthorityDenied)?;
        }
        let scope = state
            .metadata
            .get(&id)
            .ok_or(Failure::NoGrant)?
            .scope
            .clone();
        progress.entered();
        // Availability is published before DETACH, but release custody remains
        // native-owner-bound until the successful release witness commits.
        state
            .metadata
            .get_mut(&id)
            .and_then(|metadata| metadata.launch_owner.as_mut())
            .ok_or(Failure::AuthorityDenied)?
            .phase = if bootstrap.is_some() {
            LaunchPhase::BootstrapAwaitingRelease
        } else {
            LaunchPhase::DirectAwaitingRelease
        };
        state
            .metadata
            .get_mut(&id)
            .and_then(|metadata| metadata.launch_owner.as_mut())
            .ok_or(Failure::AuthorityDenied)?
            .release_deadline = Some(
            observed
                .checked_add(Duration::from_secs(15))
                .ok_or(Failure::InvalidRequest)?,
        );
        if let Err(failure) = write_marker(service, &scope, id) {
            stop_uncommitted_launch(service, &mut state, id, observed)?;
            return Err(failure);
        }
        state.selected.insert(scope, id);
        progress.changed();
    }
    if let Some(bootstrap) = bootstrap.take() {
        let result = finish_bootstrap_release(service, caller, id, bootstrap).await;
        if let Err(failure) = result {
            let mut state = service.state.lock().await;
            stop_uncommitted_launch(service, &mut state, id, now()?)?;
            return Err(failure);
        }
    }
    let state = service.state.lock().await;
    let mut response = ControlResult::success("activate_launch", true);
    response.grant = Some(snapshot(&state, id, now()?)?);
    Ok(response)
}

fn require_launch_state(
    service: &Service,
    state: &State,
    id: GrantId,
    caller: &Caller,
    phase: LaunchPhase,
) -> Result<(), Failure> {
    if state.stopping
        || !policy_unchanged(service)
        || state
            .registry
            .get(id)
            .ok_or(Failure::NoGrant)?
            .lifetime
            .state()
            != LeaseState::Active
        || !state
            .metadata
            .get(&id)
            .and_then(|metadata| metadata.launch_owner.as_ref())
            .is_some_and(|owner| {
                owner.phase == phase
                    && owner.matches(caller)
                    && (phase == LaunchPhase::Pending || owner.available())
            })
    {
        return Err(Failure::AuthorityDenied);
    }
    Ok(())
}

async fn finish_bootstrap_release(
    service: &Service,
    caller: &Caller,
    id: GrantId,
    bootstrap: VerifiedBootstrap,
) -> Result<(), Failure> {
    {
        let mut state = service.state.lock().await;
        state.registry.poll(now()?);
        require_launch_state(
            service,
            &state,
            id,
            caller,
            LaunchPhase::BootstrapAwaitingRelease,
        )?;
        bootstrap
            .proof
            .recheck(&bootstrap.owner)
            .map_err(|_| Failure::AuthorityDenied)?;
        // This is a private newly-created nonblocking FIFO. It cannot block a
        // runtime worker on a borrowed/full endpoint, and changes no caller sink.
        if nix::unistd::write(&bootstrap.release, &[1]) != Ok(1) {
            return Err(Failure::RuntimeFailure);
        }
    }
    let bootstrap = tokio::task::spawn_blocking(move || {
        crate::supervisor::startup_proof::await_release_witness(
            &bootstrap.socket,
            &bootstrap.owner,
            &bootstrap.proof,
        )?;
        Ok::<_, anyhow::Error>(bootstrap)
    })
    .await
    .map_err(|_| Failure::NativeUnavailable)?
    .map_err(|_| Failure::AuthorityDenied)?;
    let mut state = service.state.lock().await;
    state.registry.poll(now()?);
    require_launch_state(
        service,
        &state,
        id,
        caller,
        LaunchPhase::BootstrapAwaitingRelease,
    )?;
    bootstrap
        .proof
        .recheck(&bootstrap.owner)
        .map_err(|_| Failure::AuthorityDenied)?;
    crate::supervisor::startup_proof::send_commit_receipt(&bootstrap.socket)
        .map_err(|_| Failure::RuntimeFailure)?;
    // The installed monitor proved successful native DETACH, and remains alive
    // until this receipt. Fast payload exit therefore cannot invalidate proof.
    state
        .metadata
        .get_mut(&id)
        .ok_or(Failure::NoGrant)?
        .launch_owner = None;
    Ok(())
}

async fn commit_launch(
    service: &Service,
    caller: &Caller,
    submitted: &str,
    progress: &mut Progress,
) -> Result<ControlResult, Failure> {
    let _setup = setup_admission(service)?;
    let id = parse_id(submitted)?;
    let mut state = service.state.lock().await;
    state.registry.poll(now()?);
    // Only the exact installed owning caller reaches this request after its
    // borrowed-child callback has successfully detached the native exec stop.
    require_launch_state(
        service,
        &state,
        id,
        caller,
        LaunchPhase::DirectAwaitingRelease,
    )?;
    progress.entered();
    state
        .metadata
        .get_mut(&id)
        .ok_or(Failure::NoGrant)?
        .launch_owner = None;
    progress.changed();
    let mut response = ControlResult::success("commit_launch", true);
    response.grant = Some(snapshot(&state, id, now()?)?);
    Ok(response)
}

fn stop_uncommitted_launch(
    service: &Service,
    state: &mut State,
    id: GrantId,
    now: Duration,
) -> Result<(), Failure> {
    if state
        .metadata
        .get(&id)
        .is_none_or(|metadata| metadata.launch_owner.is_none())
    {
        return Ok(());
    }
    state
        .registry
        .stop(id, StopReason::WorkloadEnded, now)
        .map_err(session_failure)?;
    let metadata = state.metadata.get_mut(&id).ok_or(Failure::NoGrant)?;
    let stopped = metadata.boundary.stop().map_err(|_| Failure::CleanupFailed);
    if state.selected.get(&metadata.scope) == Some(&id) {
        remove_marker(service, &metadata.scope)?;
        state.selected.remove(&metadata.scope);
    }
    stopped?;
    // Revoked authority remains owned by the registry/boundary cleanup state;
    // no release commit can revive it. Do not retain startup-only owner after
    // successful withdrawal and revisit an already removed grant boundary.
    state
        .metadata
        .get_mut(&id)
        .ok_or(Failure::NoGrant)?
        .launch_owner = None;
    Ok(())
}

fn sweep_abandoned_launches_locked(
    service: &Service,
    state: &mut State,
    now: Duration,
) -> Result<(), Failure> {
    state.registry.poll(now);
    let abandoned: Vec<_> = state
        .metadata
        .iter()
        .filter_map(|(id, metadata)| {
            metadata
                .launch_owner
                .as_ref()
                .filter(|owner| {
                    owner.revocation_reason().is_some()
                        || state
                            .registry
                            .get(*id)
                            .is_none_or(|grant| grant.lifetime.state() != LeaseState::Active)
                })
                .map(|_| *id)
        })
        .collect();
    for id in abandoned {
        stop_uncommitted_launch(service, state, id, now)?;
    }
    Ok(())
}

async fn sweep_abandoned_launches(service: &Service) -> Result<(), Failure> {
    let mut state = service.state.lock().await;
    sweep_abandoned_launches_locked(service, &mut state, now()?)
}

async fn observe(
    service: &Service,
    caller: &Caller,
    selected: Option<&str>,
) -> Result<ControlResult, Failure> {
    let mut state = service.state.lock().await;
    let now = now()?;
    state.registry.poll(now);
    let mut response = ControlResult::success(
        if selected.is_some() {
            "inspect"
        } else {
            "status"
        },
        false,
    );
    if let Some(id) = selected {
        let id = parse_id(id)?;
        require_owner(&state, id, &caller.scope.account)?;
        response.grant = Some(snapshot(&state, id, now)?);
    } else {
        for grant in state
            .registry
            .iter()
            .filter(|grant| grant.scope.account == caller.scope.account)
        {
            response.grants.push(snapshot(&state, grant.id, now)?);
        }
    }
    Ok(response)
}

async fn revoke(
    service: &Service,
    caller: &Caller,
    selected: Option<&str>,
    leave: bool,
    progress: &mut Progress,
) -> Result<ControlResult, Failure> {
    let (id, scope) = {
        let mut state = service.state.lock().await;
        let id = if let Some(id) = selected {
            parse_id(id)?
        } else {
            select(&state, &caller.scope, None)?
        };
        if leave && state.registry.get(id).is_none() {
            let scope = state
                .selected
                .iter()
                .find_map(|(scope, selected)| {
                    (*selected == id && scope.account == caller.scope.account)
                        .then(|| scope.clone())
                })
                .ok_or(Failure::NoGrant)?;
            // Startup proved all old process boundaries empty. A retired
            // record is also removed only after confirmed cleanup. Leaving
            // stale routing is safe but never issues replacement authority.
            progress.entered();
            remove_marker(service, &scope)?;
            state.selected.remove(&scope);
            progress.changed();
            return Ok(ControlResult::success("leave", true));
        }
        require_owner(&state, id, &caller.scope.account)?;
        let scope = state
            .metadata
            .get(&id)
            .ok_or(Failure::NoGrant)?
            .scope
            .clone();
        state
            .registry
            .stop(id, StopReason::Revoked, now()?)
            .map_err(session_failure)?;
        progress.changed();
        (id, scope)
    };
    for _ in 0..50 {
        reap(service).await?;
        let mut state = service.state.lock().await;
        let grant = state.registry.get(id).ok_or(Failure::NoGrant)?;
        if grant.lifetime.state().is_terminal() {
            let mut response = ControlResult::success(if leave { "leave" } else { "revoke" }, true);
            response.grant = Some(snapshot(&state, id, now()?)?);
            if leave {
                remove_marker(service, &scope)?;
                if state.selected.get(&scope) == Some(&id) {
                    state.selected.remove(&scope);
                }
            }
            return Ok(response);
        }
        drop(state);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Failure::CleanupFailed)
}

async fn delegate(
    service: &Service,
    caller: &Caller,
    parent: &str,
    mut request: GrantRequest,
    progress: &mut Progress,
) -> Result<ControlResult, Failure> {
    let _setup = setup_admission(service)?;
    let parent = parse_id(parent)?;
    if !service
        .policy
        .subject(&caller.scope.account)?
        .allow_delegation
    {
        return Err(Failure::AuthorityDenied);
    }
    let scope = requested_scope(caller, request.scope)?;
    let limits = service
        .policy
        .approve_limits(&caller.scope.account, &request)?;
    request.idle_seconds = effective_idle(&service.policy, &scope.account, &request)?;
    let now = now()?;
    let id = new_id()?;
    let mut state = service.state.lock().await;
    if state.stopping {
        return Err(Failure::NativeUnavailable);
    }
    if depth(&state, parent) >= 16 {
        return Err(Failure::Busy);
    }
    select(&state, &caller.scope, Some(&format!("{parent:032x}")))?;
    let source = state.metadata.get(&parent).ok_or(Failure::NoGrant)?;
    if source
        .launch_owner
        .as_ref()
        .is_some_and(|owner| !owner.available())
    {
        return Err(Failure::AuthorityDenied);
    }
    let boundary = ExecutionBoundary::create(
        source.boundary.directory(),
        &format!("grant-{id:032x}"),
        now.checked_add(limits.hard_timeout())
            .ok_or(Failure::InvalidRequest)?,
    )
    .map_err(|_| Failure::NativeUnavailable)?;
    let workload = if scope.workload.is_some() {
        caller
            .workload
            .as_ref()
            .map(File::try_clone)
            .transpose()
            .map_err(|_| Failure::RuntimeFailure)?
    } else {
        None
    };
    state
        .registry
        .delegate(
            parent,
            &caller.scope,
            id,
            scope.clone(),
            request.authority.clone(),
            limits,
            request.uses.and_then(NonZeroU64::new),
            now,
        )
        .map_err(session_failure)?;
    progress.changed();
    state.metadata.insert(
        id,
        Metadata {
            request,
            scope,
            boundary,
            workload,
            terminal_since: None,
            launch_owner: None,
        },
    );
    let mut response = ControlResult::success("delegate", true);
    response.grant = Some(snapshot(&state, id, now)?);
    Ok(response)
}

enum RequestedExecution {
    Command(super::Execution),
    SudoRelay(super::Execution),
    Plan {
        authority: Authority,
        terminal: bool,
    },
}

async fn execute(
    service: &Arc<Service>,
    caller: &Caller,
    selected: Option<&str>,
    execution: RequestedExecution,
    streams: Vec<OwnedFd>,
    connection: &OwnedFd,
    progress: &mut Progress,
) -> Result<ControlResult, Failure> {
    let (execution, sudo_relay, plan_authority) = match execution {
        RequestedExecution::Command(execution) => (execution, false, None),
        RequestedExecution::SudoRelay(execution) => (execution, true, None),
        RequestedExecution::Plan {
            authority,
            terminal,
        } => (
            super::Execution {
                program: "dev-auth".into(),
                arguments: vec!["grant-plan-worker".into(), std::ffi::OsString::new()],
                working_directory: std::fs::read_link(format!("/proc/{}/cwd", caller.peer.pid))
                    .map_err(|_| Failure::AuthorityDenied)?
                    .into_os_string(),
                environment: vec![],
                terminal,
            },
            false,
            Some(authority),
        ),
    };
    let setup_lease = setup_admission(service)?;
    let graph_execution = plan_authority.is_some();
    if streams.len() != 4 {
        return Err(Failure::InvalidRequest);
    }
    let terminal = execution.terminal;
    caller.verify_directory(&execution.working_directory)?;
    let now = now()?;
    let job_id = new_id()?;
    let (
        grant_id,
        permit,
        context,
        command,
        streams,
        events,
        master,
        hard_deadline,
        captured_relay,
    ) = {
        let mut state = service.state.lock().await;
        if state.stopping || state.jobs.len() >= MAX_EXECUTIONS {
            return Err(Failure::Busy);
        }
        let grant_id = select(&state, &caller.scope, selected)?;
        if sudo_relay {
            // This is continuation of a verified native sudo preflight, not a
            // public alternative root runner. Copied grant IDs cannot select
            // the relay when sudo's mandatory bridge was never present.
            let pending = state
                .pending_relays
                .remove(&caller.peer.pid)
                .ok_or(Failure::AuthorityDenied)?;
            let frontend = File::open(format!("/proc/{}/exe", caller.peer.pid))
                .map_err(|_| Failure::AuthorityDenied)?;
            if pending.grant != grant_id
                || now >= pending.expires
                || !native::alive(pending.caller.peer.peer_pidfd())
                || pending.caller.scope != caller.scope
                || pending.caller.peer.unified_cgroup != caller.peer.unified_cgroup
                || !native::same_file(&pending.caller.user_namespace, &caller.user_namespace)?
                || !native::same_file(&pending.caller.mount_namespace, &caller.mount_namespace)?
                || !native::same_file(&pending.caller.directory, &caller.directory)?
                || !native::same_file(&frontend, &service.product_file)?
            {
                return Err(Failure::AuthorityDenied);
            }
        }
        let grant = state.registry.get(grant_id).ok_or(Failure::NoGrant)?;
        let graph = plan_authority
            .as_ref()
            .map(|selected| super::graph::select(&service.policy, grant.authority, selected))
            .transpose()?;
        let output_limit = graph.as_ref().and_then(|plan| plan.output_limit_bytes);
        let (authority, mut command) = if let Some(selected) = &plan_authority {
            (selected.clone(), execution)
        } else if sudo_relay {
            // This preparation only starts held native sudo as the original
            // non-root account. The native plugin still checks its post-policy
            // command against this same selected grant before any elevation.
            (grant.authority.clone(), execution)
        } else {
            execution_authority(&service.policy, grant.authority, execution)?
        };
        if command.terminal != terminal {
            return Err(Failure::AuthorityDenied);
        }
        let (streams, events, master) = super::execution_io::prepare_streams(streams, terminal)?;
        state
            .registry
            .admit(grant_id, &caller.scope, &authority, now)
            .map_err(session_failure)?;
        progress.changed();
        let metadata = state.metadata.get(&grant_id).ok_or(Failure::NoGrant)?;
        let deadline = state
            .registry
            .get(grant_id)
            .ok_or(Failure::NoGrant)?
            .lifetime
            .hard_deadline();
        let boundary = ExecutionBoundary::create(
            metadata.boundary.directory(),
            &format!("exec-{job_id:032x}"),
            deadline,
        )
        .map_err(|_| Failure::NativeUnavailable)?;
        let mut gates = vec![
            native::clone_fd(&service.coordinator)?,
            native::clone_fd(caller.peer.peer_pidfd())?,
            native::clone_fd(connection)?,
        ];
        let mut ancestor = Some(grant_id);
        while let Some(id) = ancestor {
            gates.push(
                state
                    .metadata
                    .get(&id)
                    .ok_or(Failure::NoGrant)?
                    .boundary
                    .gate()
                    .map_err(|_| Failure::RuntimeFailure)?,
            );
            ancestor = state.registry.get(id).ok_or(Failure::NoGrant)?.parent;
        }
        let relay_gates = output_limit
            .map(|_| {
                gates
                    .iter()
                    .map(native::clone_fd)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let permit = boundary
            .permit(gates)
            .map_err(|_| Failure::AuthorityDenied)?;
        let inherited_files = if let Some(plan) = graph {
            let prepared = super::graph::prepare(plan, deadline, terminal)?;
            command.arguments[1] = prepared.snapshot.as_raw_fd().to_string().into();
            let mut inherited = vec![prepared.snapshot];
            inherited.extend(prepared.null_device);
            inherited
        } else {
            vec![]
        };
        let context = dev_tools_privilege_session::linux::NativeContext {
            working_directory: caller
                .directory
                .try_clone()
                .map_err(|_| Failure::RuntimeFailure)?,
            mount_namespace: Some(
                caller
                    .mount_namespace
                    .try_clone()
                    .map_err(|_| Failure::RuntimeFailure)?,
            ),
            uid: if sudo_relay { caller.peer.uid } else { 0 },
            // The held native sudo image starts with its ordinary real user
            // and host effective root identity. Mount namespaces owned by a
            // workload user namespace cannot supply setuid elevation to a
            // process remaining in the host user namespace. Authority here
            // comes from the approved grant and retained sudo image, not suid.
            effective_uid: 0,
            gid: if sudo_relay {
                caller.peer.gid
            } else {
                nix::unistd::Gid::effective().as_raw()
            },
            supplementary_groups: if sudo_relay {
                caller.groups()?
            } else {
                nix::unistd::getgroups()
                    .map_err(|_| Failure::NativeUnavailable)?
                    .into_iter()
                    .map(nix::unistd::Gid::as_raw)
                    .collect()
            },
            controlling_terminal: terminal,
            inherited_files,
        };
        let (streams, master, captured_relay, captured) = if let Some(limit) = output_limit {
            let prepared = super::output::prepare(
                limit,
                streams,
                master,
                boundary
                    .stop_handles()
                    .map_err(|_| Failure::NativeUnavailable)?,
            )?;
            let relay_permit = boundary
                .permit(relay_gates.ok_or(Failure::RuntimeFailure)?)
                .map_err(|_| Failure::AuthorityDenied)?;
            let image = service
                .product_file
                .try_clone()
                .map_err(|_| Failure::NativeUnavailable)?;
            let captured = CapturedJob {
                counters: prepared.counters,
                worker: None,
                relay: None,
                worker_status: None,
                relay_status: None,
                spawn_finished: false,
                spawn_failed: false,
                wait_failed: false,
                cleanup_failed: false,
                stopped: None,
                published: false,
                drain: super::output::DrainSettlement::default(),
                drain_failed: false,
                connection: native::clone_fd(connection)?,
                boundary_removed: false,
            };
            (
                prepared.streams,
                prepared.master,
                Some((prepared.relay, relay_permit, image)),
                Some(captured),
            )
        } else {
            (streams, master, None, None)
        };
        state.jobs.insert(
            job_id,
            Job {
                grant: grant_id,
                boundary,
                preparing: true,
                leader_done: false,
                external_leader: None,
                external_complete: false,
                origin: caller.scope.clone(),
                relay: if sudo_relay {
                    RelayAdmission::Preparing
                } else {
                    RelayAdmission::Ordinary
                },
                captured,
            },
        );
        (
            grant_id,
            permit,
            context,
            command,
            streams,
            events,
            master,
            deadline,
            captured_relay,
        )
    };
    let started = super::execution_io::Started {
        schema: super::execution_io::START_SCHEMA.to_owned(),
        hard_deadline_milliseconds: u64::try_from(hard_deadline.as_millis())
            .map_err(|_| Failure::InvalidRequest)?,
        terminal,
    };
    let sent = (|| {
        let bytes = serde_json::to_vec(&started).map_err(|_| Failure::RuntimeFailure)?;
        let descriptors: Vec<_> = master.iter().map(AsRawFd::as_raw_fd).collect();
        let controls = if descriptors.is_empty() {
            Vec::new()
        } else {
            vec![socket::ControlMessage::ScmRights(&descriptors)]
        };
        let count = socket::sendmsg::<UnixAddr>(
            connection.as_raw_fd(),
            &[std::io::IoSlice::new(&bytes)],
            &controls,
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .map_err(|_| Failure::RuntimeFailure)?;
        if count != bytes.len() {
            return Err(Failure::ProtocolViolation);
        }
        Ok(())
    })();
    drop(master);
    if let Err(failure) = sent {
        let mut state = service.state.lock().await;
        if let Some(job) = state.jobs.get_mut(&job_id) {
            job.preparing = false;
            job.leader_done = true;
            if let Some(captured) = &mut job.captured {
                captured.spawn_finished = true;
                captured.spawn_failed = true;
                captured.published = true;
            }
            let _ = job.boundary.stop();
        }
        return Err(failure);
    }
    if let Some((relay, relay_permit, relay_image)) = captured_relay {
        return execute_captured(
            service,
            caller,
            connection,
            events,
            job_id,
            grant_id,
            hard_deadline,
            permit,
            context,
            command,
            streams,
            relay,
            relay_permit,
            relay_image,
            setup_lease,
        )
        .await;
    }
    let held_sudo = if graph_execution {
        Some(
            service
                .product_file
                .try_clone()
                .map_err(|_| Failure::NativeUnavailable)?,
        )
    } else if sudo_relay {
        Some(
            service
                .sudo_file
                .try_clone()
                .map_err(|_| Failure::NativeUnavailable)?,
        )
    } else {
        None
    };
    let spawned = tokio::task::spawn_blocking(move || {
        if let Some(executable) = held_sudo {
            permit.spawn_held(
                executable,
                &command.program,
                &command.arguments,
                &command.environment,
                context,
                streams,
            )
        } else {
            permit.spawn(
                &command.program,
                &command.arguments,
                &command.environment,
                context,
                streams,
            )
        }
    })
    .await;
    let child = {
        let mut state = service.state.lock().await;
        let job = state.jobs.get_mut(&job_id).ok_or(Failure::RuntimeFailure)?;
        job.preparing = false;
        match spawned {
            Ok(Ok(child)) => {
                if sudo_relay {
                    job.relay = RelayAdmission::Ready(child.id());
                }
                child
            }
            _ => {
                job.leader_done = true;
                let _ = job.boundary.stop();
                return Err(Failure::RuntimeFailure);
            }
        }
    };
    drop(setup_lease);
    let status = loop {
        if self::now()? >= hard_deadline {
            let mut state = service.state.lock().await;
            state
                .registry
                .stop(grant_id, StopReason::HardExpired, self::now()?)
                .map_err(session_failure)?;
            if let Some(metadata) = state.metadata.get_mut(&grant_id) {
                let _ = metadata.boundary.stop();
            }
        }
        if !caller.still_present() || connection_closed(connection) {
            let mut state = service.state.lock().await;
            if let Some(job) = state.jobs.get_mut(&job_id) {
                let _ = job.boundary.stop();
            }
        }
        match super::execution_io::receive_signal(&events) {
            Ok(Some(signal)) => {
                let mut state = service.state.lock().await;
                if let Some(job) = state.jobs.get_mut(&job_id) {
                    if job.boundary.signal(signal).is_err() {
                        let _ = job.boundary.stop();
                    }
                }
            }
            Ok(None) => {}
            Err(_) => {
                let mut state = service.state.lock().await;
                if let Some(job) = state.jobs.get_mut(&job_id) {
                    let _ = job.boundary.stop();
                }
            }
        }
        // This task is the sole waiter for its directly spawned child. An
        // unreaped child PID cannot be reused; stop/continue notifications are
        // consumed here and final waitpid status is the join witness.
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        match waitpid(
            nix::unistd::Pid::from_raw(child.id() as i32),
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
        ) {
            Ok(WaitStatus::Exited(_, code)) => break std::process::ExitStatus::from_raw(code << 8),
            Ok(WaitStatus::Signaled(_, signal, core)) => {
                break std::process::ExitStatus::from_raw(
                    signal as i32 | if core { 0x80 } else { 0 },
                )
            }
            Ok(WaitStatus::Stopped(_, signal)) => {
                if super::execution_io::report_stopped(&events, signal).is_err() {
                    let mut state = service.state.lock().await;
                    if let Some(job) = state.jobs.get_mut(&job_id) {
                        let _ = job.boundary.stop();
                    }
                }
            }
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(_) => {
                let mut state = service.state.lock().await;
                if let Some(job) = state.jobs.get_mut(&job_id) {
                    job.leader_done = true;
                    let _ = job.boundary.stop();
                }
                return Err(Failure::RuntimeFailure);
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    {
        let mut state = service.state.lock().await;
        if let Some(job) = state.jobs.get_mut(&job_id) {
            job.leader_done = true;
            if graph_execution && !status.success() {
                job.boundary.stop().map_err(|_| Failure::CleanupFailed)?;
            }
        }
    }
    if graph_execution && !status.success() {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let empty = {
                let state = service.state.lock().await;
                state
                    .jobs
                    .get(&job_id)
                    .map(|job| job.boundary.is_empty())
                    .transpose()
                    .map_err(|_| Failure::CleanupFailed)?
                    .unwrap_or(true)
            };
            if empty {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(Failure::CleanupFailed);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    reap(service).await?;
    let state = service.state.lock().await;
    let mut response = ControlResult::success("exec", true);
    response.child_exit_code = status.code();
    response.child_signal = status.signal();
    response.grant = state
        .registry
        .get(grant_id)
        .map(|_| snapshot(&state, grant_id, self::now()?))
        .transpose()?;
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn execute_captured(
    service: &Arc<Service>,
    caller: &Caller,
    connection: &OwnedFd,
    events: OwnedFd,
    job_id: GrantId,
    grant_id: GrantId,
    hard_deadline: Duration,
    permit: dev_tools_privilege_session::linux::SpawnPermit,
    context: dev_tools_privilege_session::linux::NativeContext,
    command: super::Execution,
    streams: [OwnedFd; 3],
    relay: super::output::Relay,
    relay_permit: dev_tools_privilege_session::linux::SpawnPermit,
    relay_image: File,
    setup_lease: Option<dev_tools_installation::InstallationLock>,
) -> Result<ControlResult, Failure> {
    let owner = Arc::clone(service);
    let spawned = tokio::task::spawn_blocking(move || {
        let worker = owner.product_file.try_clone().and_then(|image| {
            permit.spawn_held(
                image,
                &command.program,
                &command.arguments,
                &command.environment,
                context,
                streams,
            )
        });
        let relay = if let Ok(worker) = &worker {
            Some(relay.spawn(relay_permit, relay_image, worker))
        } else {
            None
        };
        // Transfer both Child owners before this task yields its completion.
        // Cancelling the connection future cannot drop their join authority.
        let mut state = owner.state.blocking_lock();
        let job = state.jobs.get_mut(&job_id).ok_or(Failure::CleanupFailed)?;
        let captured = job.captured.as_mut().ok_or(Failure::CleanupFailed)?;
        captured.spawn_failed =
            worker.is_err() || relay.as_ref().is_none_or(|result| result.is_err());
        captured.worker = worker.ok();
        captured.relay = relay.and_then(Result::ok);
        captured.spawn_finished = true;
        job.preparing = false;
        if captured.spawn_failed && job.boundary.stop().is_err() {
            captured.cleanup_failed = true;
        }
        Ok::<_, Failure>(())
    })
    .await;
    drop(setup_lease);
    let mut failure = if matches!(spawned, Ok(Ok(()))) {
        None
    } else {
        Some(Failure::RuntimeFailure)
    };
    let mut cleanup_deadline = failure.map(|_| std::time::Instant::now() + Duration::from_secs(5));
    loop {
        let expired = !self::now().is_ok_and(|now| now < hard_deadline);
        let disconnected = !caller.still_present() || connection_closed(connection);
        let signal = super::execution_io::receive_signal(&events);
        let mut state = service.state.lock().await;
        let job = state.jobs.get_mut(&job_id).ok_or(Failure::CleanupFailed)?;
        let stop = expired || disconnected || signal.is_err() || failure.is_some();
        if stop {
            if failure.is_none() {
                failure = Some(if expired {
                    Failure::GrantExpired
                } else {
                    Failure::Interrupted
                });
            }
            cleanup_deadline
                .get_or_insert_with(|| std::time::Instant::now() + Duration::from_secs(5));
            if job.boundary.stop().is_err() {
                job.captured
                    .as_mut()
                    .ok_or(Failure::CleanupFailed)?
                    .cleanup_failed = true;
            }
        } else if let Ok(Some(signal)) = signal {
            if job.boundary.signal(signal).is_err() {
                failure = Some(Failure::RuntimeFailure);
                cleanup_deadline
                    .get_or_insert_with(|| std::time::Instant::now() + Duration::from_secs(5));
                if job.boundary.stop().is_err() {
                    job.captured
                        .as_mut()
                        .ok_or(Failure::CleanupFailed)?
                        .cleanup_failed = true;
                }
            }
        }
        poll_captured(job);
        let captured = job.captured.as_mut().ok_or(Failure::CleanupFailed)?;
        if let Some(signal) = captured.stopped.take() {
            if super::execution_io::report_stopped(&events, signal).is_err() {
                failure = Some(Failure::Interrupted);
            }
        }
        if captured.counters.exceeded() {
            failure = Some(Failure::OutputLimit);
            cleanup_deadline
                .get_or_insert_with(|| std::time::Instant::now() + Duration::from_secs(5));
        } else if captured.spawn_failed
            || captured.drain_failed
            || captured.wait_failed
            || captured.counters.failed()
            || captured
                .relay_status
                .as_ref()
                .is_some_and(|status| !status.success())
        {
            failure.get_or_insert(Failure::RuntimeFailure);
            cleanup_deadline
                .get_or_insert_with(|| std::time::Instant::now() + Duration::from_secs(5));
        }
        let joined = job.leader_done;
        let empty = if joined {
            match job.boundary.is_empty() {
                Ok(empty) => empty,
                Err(_) => {
                    captured.cleanup_failed = true;
                    false
                }
            }
        } else {
            false
        };
        let timed_out =
            cleanup_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline);
        if joined && !empty {
            cleanup_deadline
                .get_or_insert_with(|| std::time::Instant::now() + Duration::from_secs(5));
        }
        if (joined && empty) || timed_out {
            let mut output = captured.counters.observation(joined)?;
            if captured.drain_failed {
                output.complete = false;
            }
            // Positive emptiness and both joins precede namespace removal. A
            // failed removal is cleanup failure, never a successful result.
            if joined && empty {
                if job.boundary.remove().is_err() {
                    captured.cleanup_failed = true;
                } else {
                    captured.boundary_removed = true;
                }
            }
            if !joined || !empty || captured.cleanup_failed || captured.counters.cleanup_failed() {
                failure = Some(Failure::CleanupFailed);
                captured.cleanup_failed = true;
                output.complete = false;
            } else if !output.complete && failure.is_none() {
                failure = Some(Failure::RuntimeFailure);
            }
            let worker_status = captured.worker_status;
            captured.published = true;
            let mut response = failure
                .map(|failure| ControlResult::failure("exec", failure, Some(true)))
                .unwrap_or_else(|| ControlResult::success("exec", true));
            response.output = Some(output);
            response.child_exit_code = worker_status.and_then(|status| status.code());
            response.child_signal = worker_status.and_then(|status| status.signal());
            response.grant = state
                .registry
                .get(grant_id)
                .map(|_| snapshot(&state, grant_id, self::now()?))
                .transpose()?;
            drop(state);
            // Normal completion publishes only after both children and their
            // stream writers terminalize. Teardown removes the empty job; a
            // failed bounded join keeps its Child owners in State for reap.
            reap(service).await?;
            return Ok(response);
        }
        drop(state);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn poll_captured(job: &mut Job) {
    let Some(captured) = job.captured.as_mut() else {
        return;
    };
    if !captured.spawn_finished {
        return;
    }
    if connection_closed(&captured.connection) {
        // No response reader remains; retain sole Child wait custody until
        // terminal cleanup, then allow the reaper to release this job record.
        captured.published = true;
        if !captured.boundary_removed && job.boundary.stop().is_err() {
            captured.cleanup_failed = true;
        }
    }
    poll_owned_child(
        &mut captured.worker,
        &mut captured.worker_status,
        &mut captured.wait_failed,
        &mut captured.stopped,
    );
    let mut relay_stopped = None;
    poll_owned_child(
        &mut captured.relay,
        &mut captured.relay_status,
        &mut captured.wait_failed,
        &mut relay_stopped,
    );
    let relay_failed = captured
        .relay_status
        .as_ref()
        .is_some_and(|status| !status.success());
    if captured.relay.is_some()
        && captured
            .drain
            .observe(captured.worker_status.is_some(), std::time::Instant::now())
    {
        captured.drain_failed = true;
    }
    if !captured.boundary_removed
        && (captured.spawn_failed
            || captured.wait_failed
            || captured.counters.failed()
            || relay_failed
            || captured.drain_failed)
        && job.boundary.stop().is_err()
    {
        captured.cleanup_failed = true;
    }
    job.leader_done =
        captured.worker.is_none() && captured.relay.is_none() && !captured.wait_failed;
    if job.leader_done && !captured.boundary_removed && job.boundary.stop().is_err() {
        captured.cleanup_failed = true;
    }
}

fn poll_owned_child(
    owner: &mut Option<std::process::Child>,
    status: &mut Option<std::process::ExitStatus>,
    failed: &mut bool,
    stopped: &mut Option<nix::sys::signal::Signal>,
) {
    let Some(child) = owner.as_ref() else {
        return;
    };
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    match waitpid(
        nix::unistd::Pid::from_raw(child.id() as i32),
        Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
    ) {
        Ok(WaitStatus::Exited(_, code)) => {
            *status = Some(std::process::ExitStatus::from_raw(code << 8));
            owner.take();
        }
        Ok(WaitStatus::Signaled(_, signal, core)) => {
            *status = Some(std::process::ExitStatus::from_raw(
                signal as i32 | if core { 0x80 } else { 0 },
            ));
            owner.take();
        }
        Ok(WaitStatus::Stopped(_, signal)) => {
            *stopped = Some(signal);
        }
        Ok(_) | Err(nix::errno::Errno::EINTR) => {}
        Err(_) => {
            *failed = true;
        } // Retain ownership; ECHILD is no join proof.
    }
}

struct PendingApproval<'a> {
    pending: &'a std::sync::Mutex<BTreeSet<Account>>,
    account: Account,
}

impl Drop for PendingApproval<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&self.account);
        }
    }
}

fn connection_closed(connection: &OwnedFd) -> bool {
    use std::os::fd::AsFd;
    let mut descriptors = [nix::poll::PollFd::new(
        connection.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    !matches!(
        nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::ZERO),
        Ok(0)
    )
}

fn execution_authority(
    policy: &Policy,
    authority: &Authority,
    requested: super::Execution,
) -> Result<(Authority, super::Execution), Failure> {
    if matches!(authority, Authority::Administrator) {
        return Ok((Authority::Administrator, requested));
    }
    let candidates: Vec<(Authority, &super::policy::ExecutionPlan)> = match authority {
        Authority::ExactPlan { sha256 } => vec![(
            authority.clone(),
            policy.plans.get(sha256).ok_or(Failure::AuthorityDenied)?,
        )],
        Authority::Typed { operations } => operations
            .iter()
            .filter_map(|name| {
                policy.operations.get(name).map(|plan| {
                    (
                        Authority::Typed {
                            operations: vec![name.clone()],
                        },
                        plan,
                    )
                })
            })
            .collect(),
        Authority::Administrator => unreachable!(), // INVARIANT: the administrator authority returned before this match.
    };
    for (authority, plan) in candidates {
        // Selected plan effects are never equivalent to direct argv/native sudo:
        // graph execution owns the approved capture, identity and stream setup.
        if plan.output_limit_bytes.is_some() || plan.nodes.len() != 1 || !plan.pipes.is_empty() {
            continue;
        }
        let node = &plan.nodes[0];
        if node.requires_graph_execution() {
            continue;
        }
        if node.program == requested.program
            && node.arguments == requested.arguments
            && node.working_directory == requested.working_directory
        {
            return Ok((
                authority,
                super::Execution {
                    program: node.program.clone(),
                    arguments: node.arguments.clone(),
                    working_directory: node.working_directory.clone(),
                    environment: node.environment.clone(),
                    terminal: false,
                },
            ));
        }
    }
    Err(Failure::AuthorityDenied)
}

async fn reap(service: &Service) -> Result<(), Failure> {
    let now = now()?;
    let mut state = service.state.lock().await;
    state.pending_relays.retain(|_, pending| {
        now < pending.expires && native::alive(pending.caller.peer.peer_pidfd())
    });
    if !policy_unchanged(service) {
        state.registry.stop_all(StopReason::AuthorityChanged, now);
    }
    let ended: Vec<_> = state
        .metadata
        .iter()
        .filter_map(|(id, metadata)| {
            metadata
                .workload
                .as_ref()
                .and_then(|workload| match cgroup_empty(workload) {
                    Ok(false) => None,
                    Ok(true) => Some((*id, StopReason::WorkloadEnded)),
                    Err(_) => Some((*id, StopReason::AuthorityChanged)),
                })
        })
        .collect();
    for (id, reason) in ended {
        state
            .registry
            .stop(id, reason, now)
            .map_err(session_failure)?;
    }
    sweep_abandoned_launches_locked(service, &mut state, now)?;
    state.registry.poll(now);
    let stopped: BTreeSet<_> = state
        .registry
        .iter()
        .filter(|grant| grant.lifetime.state() != LeaseState::Active)
        .map(|grant| grant.id)
        .collect();
    for (id, metadata) in &mut state.metadata {
        if stopped.contains(id) {
            let _ = metadata.boundary.stop();
        }
    }
    let mut completed = Vec::new();
    for (id, job) in &mut state.jobs {
        poll_captured(job);
        if job
            .external_leader
            .as_ref()
            .is_some_and(|leader| !native::alive(leader))
        {
            job.leader_done = true;
            job.preparing = false;
            if !job.external_complete {
                let _ = job.boundary.stop();
            }
        }
        if stopped.contains(&job.grant) && job.boundary.stop().is_err() {
            if let Some(captured) = &mut job.captured {
                captured.cleanup_failed = true;
            }
        }
        if !job.preparing
            && job.leader_done
            && job
                .captured
                .as_ref()
                .is_none_or(|captured| captured.published)
            && (job
                .captured
                .as_ref()
                .is_some_and(|captured| captured.boundary_removed)
                || job.boundary.is_empty().unwrap_or(false))
        {
            let removed = job
                .captured
                .as_ref()
                .is_some_and(|captured| captured.boundary_removed);
            if !removed {
                let _ = job.boundary.stop();
            }
            if removed || job.boundary.remove().is_ok() {
                completed.push(*id);
            }
        }
    }
    for id in completed {
        state.jobs.remove(&id);
    }
    let mut stopping: Vec<_> = state
        .registry
        .iter()
        .filter(|grant| matches!(grant.lifetime.state(), LeaseState::Stopping { .. }))
        .map(|grant| (depth(&state, grant.id), grant.id))
        .collect();
    stopping.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, id) in stopping {
        if state.jobs.values().any(|job| job.grant == id) {
            continue;
        }
        let has_live_child = state
            .registry
            .iter()
            .any(|grant| grant.parent == Some(id) && !grant.lifetime.state().is_terminal());
        if has_live_child {
            continue;
        }
        let metadata = state.metadata.get_mut(&id).ok_or(Failure::RuntimeFailure)?;
        match metadata.boundary.is_empty() {
            Ok(true) => {
                let result = metadata.boundary.remove();
                let _ = state.registry.report_cleanup(
                    id,
                    if result.is_ok() {
                        Cleanup::Complete
                    } else {
                        Cleanup::Failed
                    },
                );
            }
            Ok(false) => {}
            Err(_) => {
                let _ = state.registry.report_cleanup(id, Cleanup::Failed);
            }
        }
    }
    let terminal: Vec<_> = state
        .registry
        .iter()
        .filter(|grant| grant.lifetime.state().is_terminal())
        .map(|grant| grant.id)
        .collect();
    for id in terminal {
        state
            .metadata
            .get_mut(&id)
            .ok_or(Failure::RuntimeFailure)?
            .terminal_since
            .get_or_insert(now);
    }
    // Keep recent terminal observations long enough for concurrent result
    // publication, but do not impose a lifetime cap of MAX_GRANTS per daemon.
    // The selected ID/marker remains fail-closed after its observation retires.
    let mut retired: Vec<_> = state
        .metadata
        .iter()
        .filter(|(_, metadata)| {
            metadata
                .terminal_since
                .is_some_and(|ended| now.saturating_sub(ended) >= Duration::from_secs(60))
        })
        .map(|(id, _)| (depth(&state, *id), *id))
        .collect();
    retired.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, id) in retired {
        if !state.jobs.values().any(|job| job.grant == id) && state.registry.retire(id).is_ok() {
            state.metadata.remove(&id);
        }
    }
    Ok(())
}

async fn check_logins(service: &Service) {
    let accounts: BTreeSet<_> = service
        .state
        .lock()
        .await
        .metadata
        .values()
        .filter(|metadata| metadata.scope.workload.is_none())
        .map(|metadata| metadata.scope.account.clone())
        .collect();
    for account in accounts {
        let Account::Unix { uid } = account else {
            continue;
        };
        if tokio::time::timeout(
            Duration::from_secs(2),
            super::approval::account_has_login(uid),
        )
        .await
            != Ok(Ok(true))
        {
            let mut state = service.state.lock().await;
            let ids: Vec<_> = state
                .metadata
                .iter()
                .filter(|(_, metadata)| {
                    metadata.scope.account == account && metadata.scope.workload.is_none()
                })
                .map(|(id, _)| *id)
                .collect();
            if let Ok(now) = now() {
                for id in ids {
                    let _ = state.registry.stop(id, StopReason::Logout, now);
                }
            }
        }
    }
}

fn requested_scope(caller: &Caller, scope: GrantScope) -> Result<NativeScope, Failure> {
    match scope {
        GrantScope::User => Ok(NativeScope {
            account: caller.scope.account.clone(),
            workload: None,
        }),
        GrantScope::Workload if caller.scope.workload.is_some() => Ok(caller.scope.clone()),
        _ => Err(Failure::AuthorityDenied),
    }
}

fn effective_idle(
    policy: &Policy,
    account: &Account,
    request: &GrantRequest,
) -> Result<Option<u64>, Failure> {
    let configured = policy.subject(account)?.idle_timeout_seconds;
    Ok(match (configured, request.idle_seconds) {
        (Some(policy), Some(request)) => Some(policy.min(request)),
        (Some(policy), None) => Some(policy),
        (None, request) => request,
    }
    .map(|idle| idle.min(request.duration_seconds)))
}

fn select(state: &State, scope: &NativeScope, requested: Option<&str>) -> Result<GrantId, Failure> {
    let id = if let Some(requested) = requested {
        parse_id(requested)?
    } else {
        state
            .selected
            .get(scope)
            .or_else(|| {
                state.selected.get(&NativeScope {
                    account: scope.account.clone(),
                    workload: None,
                })
            })
            .copied()
            .ok_or(Failure::NoGrant)?
    };
    let mut ancestor = Some(id);
    for _ in 0..=16 {
        let Some(current) = ancestor else {
            return Ok(id);
        };
        if state
            .metadata
            .get(&current)
            .and_then(|metadata| metadata.launch_owner.as_ref())
            .is_some_and(|owner| !owner.available())
        {
            return Err(Failure::AuthorityDenied);
        }
        ancestor = state.registry.get(current).and_then(|grant| grant.parent);
    }
    if ancestor.is_some() {
        return Err(Failure::AuthorityDenied);
    }
    Ok(id)
}

fn require_owner(state: &State, id: GrantId, account: &Account) -> Result<(), Failure> {
    if &state
        .registry
        .get(id)
        .ok_or(Failure::NoGrant)?
        .scope
        .account
        != account
    {
        return Err(Failure::AuthorityDenied);
    }
    Ok(())
}

fn snapshot(state: &State, id: GrantId, now: Duration) -> Result<Grant, Failure> {
    let grant = state.registry.get(id).ok_or(Failure::NoGrant)?;
    let metadata = state.metadata.get(&id).ok_or(Failure::NoGrant)?;
    let (status, stop_reason, cleanup_failed) = match grant.lifetime.state() {
        LeaseState::Active => (
            if metadata
                .launch_owner
                .as_ref()
                .is_some_and(|owner| owner.phase == LaunchPhase::Pending)
            {
                GrantState::Pending
            } else {
                GrantState::Active
            },
            None,
            false,
        ),
        LeaseState::Stopping {
            reason,
            cleanup_failed,
        } => (GrantState::Stopping, Some(reason), cleanup_failed),
        LeaseState::Terminated {
            reason,
            cleanup_failed,
        } => (GrantState::Terminated, Some(reason), cleanup_failed),
        _ => return Err(Failure::RuntimeFailure),
    };
    Ok(Grant {
        id: format!("{id:032x}"),
        scope: metadata.request.scope,
        authority: metadata.request.authority.clone(),
        state: status,
        duration_seconds: metadata.request.duration_seconds,
        remaining_milliseconds: u64::try_from(
            grant
                .lifetime
                .hard_deadline()
                .saturating_sub(now)
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
        idle_seconds: metadata.request.idle_seconds,
        remaining_uses: grant.lifetime.remaining_uses(),
        stop_reason: stop_reason.map(|reason| format!("{reason:?}")),
        cleanup_failed,
    })
}

fn depth(state: &State, mut id: GrantId) -> usize {
    let mut depth = 0;
    while let Some(parent) = state.registry.get(id).and_then(|grant| grant.parent) {
        id = parent;
        depth += 1;
    }
    depth
}

fn parse_id(id: &str) -> Result<GrantId, Failure> {
    u128::from_str_radix(id, 16).map_err(|_| Failure::InvalidRequest)
}
fn now() -> Result<Duration, Failure> {
    boot_time().map_err(|_| Failure::NativeUnavailable)
}
fn new_id() -> Result<GrantId, Failure> {
    use rsa::rand_core::RngCore;
    let mut bytes = [0_u8; 16];
    rsa::rand_core::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Failure::NativeUnavailable)?;
    Ok(u128::from_be_bytes(bytes))
}

fn session_failure(error: SessionError) -> Failure {
    match error {
        SessionError::InvalidLimits | SessionError::InvalidClock => Failure::InvalidRequest,
        SessionError::UnknownGrant => Failure::NoGrant,
        SessionError::Capacity => Failure::Busy,
        SessionError::NotActive => Failure::GrantRevoked,
        _ => Failure::AuthorityDenied,
    }
}

fn policy_unchanged(service: &Service) -> bool {
    let Ok(current) = root_file(&service.policy_path, false) else {
        return false;
    };
    FileStamp::of(&current).ok() == Some(service.policy_stamp)
        && FileStamp::of(&service.policy_file).ok() == Some(service.policy_stamp)
        && FileStamp::of(&service.sudo_file).ok() == Some(service.sudo_stamp)
        && root_file(Path::new(&service.policy.sudo_program), false)
            .ok()
            .as_ref()
            .and_then(|file| FileStamp::of(file).ok())
            == Some(service.sudo_stamp)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl FileStamp {
    fn of(file: &File) -> Result<Self, Failure> {
        let metadata = file.metadata().map_err(|_| Failure::AuthorityDenied)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mtime: metadata.mtime(),
            mtime_ns: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_ns: metadata.ctime_nsec(),
        })
    }
}

fn root_file(path: &Path, directory: bool) -> Result<File, Failure> {
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(Failure::AuthorityDenied);
    }
    for ancestor in path.parent().ok_or(Failure::AuthorityDenied)?.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| Failure::AuthorityDenied)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(Failure::AuthorityDenied);
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            nix::libc::O_CLOEXEC
                | nix::libc::O_NOFOLLOW
                | if directory { nix::libc::O_DIRECTORY } else { 0 },
        )
        .open(path)
        .map_err(|_| Failure::AuthorityDenied)?;
    let metadata = file.metadata().map_err(|_| Failure::AuthorityDenied)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(Failure::AuthorityDenied);
    }
    Ok(file)
}

fn own_service_cgroup() -> Result<PathBuf, Failure> {
    let text = String::from_utf8(native::read_bounded(Path::new("/proc/self/cgroup"), 8192)?)
        .map_err(|_| Failure::NativeUnavailable)?;
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(Failure::NativeUnavailable)?;
    if !path.starts_with("/system.slice/")
        || !path.ends_with(".service")
        || path[14..].contains('/')
    {
        return Err(Failure::NativeUnavailable);
    }
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

async fn verify_service_unit(cgroup: &Path) -> Result<(), Failure> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let unit = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnitByPID",
            &(std::process::id(),),
        )
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let unit: zbus::zvariant::OwnedObjectPath = unit
        .body()
        .deserialize()
        .map_err(|_| Failure::ProtocolViolation)?;
    let properties = zbus::fdo::PropertiesProxy::builder(&connection)
        .destination("org.freedesktop.systemd1")
        .map_err(|_| Failure::NativeUnavailable)?
        .path(unit)
        .map_err(|_| Failure::NativeUnavailable)?
        .build()
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let service_interface =
        zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Service")
            .map_err(|_| Failure::NativeUnavailable)?;
    let main_pid = properties
        .get(service_interface.clone(), "MainPID")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let kill_mode = properties
        .get(service_interface.clone(), "KillMode")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let send_kill = properties
        .get(service_interface.clone(), "SendSIGKILL")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let group = properties
        .get(service_interface.clone(), "ControlGroup")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let exit_type = properties
        .get(service_interface.clone(), "ExitType")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let remain = properties
        .get(service_interface.clone(), "RemainAfterExit")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let delegated = properties
        .get(service_interface.clone(), "Delegate")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let stop_timeout = properties
        .get(service_interface, "TimeoutStopUSec")
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let main_pid = u32::try_from(main_pid).map_err(|_| Failure::ProtocolViolation)?;
    let kill_mode = String::try_from(kill_mode).map_err(|_| Failure::ProtocolViolation)?;
    let send_kill = bool::try_from(send_kill).map_err(|_| Failure::ProtocolViolation)?;
    let group = String::try_from(group).map_err(|_| Failure::ProtocolViolation)?;
    let exit_type = String::try_from(exit_type).map_err(|_| Failure::ProtocolViolation)?;
    let remain = bool::try_from(remain).map_err(|_| Failure::ProtocolViolation)?;
    let delegated = bool::try_from(delegated).map_err(|_| Failure::ProtocolViolation)?;
    let stop_timeout = u64::try_from(stop_timeout).map_err(|_| Failure::ProtocolViolation)?;
    if main_pid != std::process::id()
        || kill_mode != "control-group"
        || !send_kill
        || exit_type != "main"
        || remain
        || delegated
        || stop_timeout > 5_000_000
        || Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')) != cgroup
    {
        return Err(Failure::NativeUnavailable);
    }
    Ok(())
}

fn cgroup_empty(directory: &File) -> Result<bool, Failure> {
    use std::os::unix::fs::FileExt;
    let fd = rustix::fs::openat(
        directory,
        "cgroup.events",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Failure::NativeUnavailable)?;
    let file = File::from(fd);
    let mut bytes = [0; 4096];
    let length = file
        .read_at(&mut bytes, 0)
        .map_err(|_| Failure::NativeUnavailable)?;
    if length == bytes.len() {
        return Err(Failure::NativeUnavailable);
    }
    parse_population(&bytes[..length])
}

fn parse_population(bytes: &[u8]) -> Result<bool, Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::NativeUnavailable)?;
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix("populated "));
    let populated = values.next().ok_or(Failure::NativeUnavailable)?;
    if values.next().is_some() {
        return Err(Failure::NativeUnavailable);
    }
    match populated {
        "0" => Ok(true),
        "1" => Ok(false),
        _ => Err(Failure::NativeUnavailable),
    }
}

fn marker_name(scope: &NativeScope) -> Result<String, Failure> {
    let Account::Unix { uid } = scope.account else {
        return Err(Failure::NativeUnavailable);
    };
    Ok(match scope.workload {
        Some(workload) => format!("workload-{uid}-{workload:032x}"),
        None => format!("user-{uid}"),
    })
}

fn parse_marker_name(name: &str) -> Result<NativeScope, Failure> {
    let (owner, workload) = if let Some(owner) = name.strip_prefix("user-") {
        (owner, None)
    } else if let Some(tail) = name.strip_prefix("workload-") {
        let (owner, workload) = tail.split_once('-').ok_or(Failure::AuthorityDenied)?;
        if workload.len() != 32
            || !workload
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Failure::AuthorityDenied);
        }
        (owner, Some(parse_id(workload)?))
    } else {
        return Err(Failure::AuthorityDenied);
    };
    let uid: u32 = owner.parse().map_err(|_| Failure::AuthorityDenied)?;
    if uid == 0 || owner != uid.to_string() {
        return Err(Failure::AuthorityDenied);
    }
    Ok(NativeScope {
        account: Account::Unix { uid },
        workload,
    })
}

fn load_markers(runtime: &Path) -> Result<BTreeMap<NativeScope, GrantId>, Failure> {
    let mut selected = BTreeMap::new();
    for entry in std::fs::read_dir(runtime).map_err(|_| Failure::NativeUnavailable)? {
        let entry = entry.map_err(|_| Failure::NativeUnavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(Failure::AuthorityDenied);
        };
        if !name.starts_with("user-") && !name.starts_with("workload-") {
            continue;
        }
        if selected.len() >= 16_384 {
            return Err(Failure::Busy);
        }
        let scope = parse_marker_name(name)?;
        let mut file = root_file(&entry.path(), false)?;
        let mut contents = String::new();
        Read::by_ref(&mut file)
            .take(34)
            .read_to_string(&mut contents)
            .map_err(|_| Failure::AuthorityDenied)?;
        if contents.len() != 33 || !contents.ends_with('\n') {
            return Err(Failure::AuthorityDenied);
        }
        let text = &contents[..32];
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Failure::AuthorityDenied);
        }
        selected.insert(scope, parse_id(text)?);
    }
    Ok(selected)
}

fn recover_cgroups(parent: &File) -> Result<(), Failure> {
    fn visit(
        directory: &File,
        depth: usize,
        count: &mut usize,
        deadline: std::time::Instant,
    ) -> Result<(), Failure> {
        if depth > 64 || *count > 16_384 || std::time::Instant::now() >= deadline {
            return Err(Failure::CleanupFailed);
        }
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| Failure::CleanupFailed)?
        {
            let entry = entry.map_err(|_| Failure::CleanupFailed)?;
            if !entry
                .file_type()
                .map_err(|_| Failure::CleanupFailed)?
                .is_dir()
            {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or(Failure::AuthorityDenied)?;
            let suffix = name
                .strip_prefix("grant-")
                .or_else(|| name.strip_prefix("exec-"))
                .ok_or(Failure::AuthorityDenied)?;
            if suffix.len() != 32
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(Failure::AuthorityDenied);
            }
            *count += 1;
            let child = File::from(
                rustix::fs::openat(
                    directory,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| Failure::CleanupFailed)?,
            );
            let metadata = child.metadata().map_err(|_| Failure::CleanupFailed)?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(Failure::AuthorityDenied);
            }
            let mut kill = File::from(
                rustix::fs::openat(
                    &child,
                    "cgroup.kill",
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| Failure::CleanupFailed)?,
            );
            kill.write_all(b"1").map_err(|_| Failure::CleanupFailed)?;
            while !cgroup_empty(&child)? {
                if std::time::Instant::now() >= deadline {
                    return Err(Failure::CleanupFailed);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            visit(&child, depth + 1, count, deadline)?;
            rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|_| Failure::CleanupFailed)?;
        }
        Ok(())
    }
    visit(
        parent,
        0,
        &mut 0,
        std::time::Instant::now() + Duration::from_secs(5),
    )
}

fn write_marker(service: &Service, scope: &NativeScope, id: GrantId) -> Result<(), Failure> {
    let temporary = service.runtime.join(format!(".routing-{id:032x}"));
    let destination = service.runtime.join(marker_name(scope)?);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| Failure::RuntimeFailure)?;
    let result = file
        .write_all(format!("{id:032x}\n").as_bytes())
        .and_then(|_| file.sync_all())
        .and_then(|_| std::fs::rename(&temporary, destination));
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result.map_err(|_| Failure::RuntimeFailure)
}

fn remove_marker(service: &Service, scope: &NativeScope) -> Result<(), Failure> {
    remove_marker_at(&service.runtime, scope)
}

fn remove_marker_at(runtime: &Path, scope: &NativeScope) -> Result<(), Failure> {
    let path = runtime.join(marker_name(scope)?);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Failure::RuntimeFailure),
    }
}

async fn send_packet(descriptor: &AsyncFd<OwnedFd>, bytes: &[u8]) -> Result<(), Failure> {
    if bytes.len() > FRAME_LIMIT {
        return Err(Failure::ProtocolViolation);
    }
    loop {
        let mut ready = descriptor
            .writable()
            .await
            .map_err(|_| Failure::NativeUnavailable)?;
        match ready.try_io(|fd| {
            socket::send(fd.get_ref().as_raw_fd(), bytes, MsgFlags::MSG_NOSIGNAL)
                .map_err(io::Error::from)
        }) {
            Ok(Ok(length)) if length == bytes.len() => return Ok(()),
            Err(_) => continue,
            _ => return Err(Failure::RuntimeFailure),
        }
    }
}

async fn receive_packet(
    descriptor: &AsyncFd<OwnedFd>,
    caller: &Caller,
) -> Result<(Envelope, Vec<OwnedFd>), Failure> {
    loop {
        let mut readiness = descriptor
            .readable()
            .await
            .map_err(|_| Failure::NativeUnavailable)?;
        let result = readiness.try_io(|fd| {
            let packet = super::transport::receive_owned(fd.get_ref())?;
            if !packet.credentials.is_some_and(|credentials| {
                credentials.pid() as u32 == caller.peer.pid
                    && credentials.uid() == caller.peer.uid
                    && credentials.gid() == caller.peer.gid
            }) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let envelope = serde_json::from_slice(&packet.bytes)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            Ok((envelope, packet.descriptors))
        });
        match result {
            Ok(Ok(packet)) => return Ok(packet),
            Err(_) => continue,
            _ => return Err(Failure::ProtocolViolation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_user_grant_is_withdrawn_when_controller_dies_before_release_commit() {
        struct OwnedController(std::process::Child);
        impl Drop for OwnedController {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for phase in [
            LaunchPhase::DirectAwaitingRelease,
            LaunchPhase::BootstrapAwaitingRelease,
        ] {
            let mut controller = OwnedController(
                std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            let pid = controller.0.id();
            let image = File::open(format!("/proc/{pid}/exe")).unwrap();
            let owner = LaunchOwner {
                pid,
                pidfd: rustix::process::pidfd_open(
                    rustix::process::Pid::from_raw(pid as i32).unwrap(),
                    rustix::process::PidfdFlags::empty(),
                )
                .unwrap(),
                scope: NativeScope {
                    account: Account::Unix {
                        uid: nix::unistd::geteuid().as_raw(),
                    },
                    workload: Some(1),
                },
                image,
                native_cgroup: crate::linux_admission::read_unified_cgroup(pid).unwrap(),
                phase,
                release_deadline: Some(now().unwrap() + Duration::from_secs(60)),
            };
            let scope = NativeScope {
                account: owner.scope.account.clone(),
                workload: None,
            };
            let runtime = tempfile::tempdir().unwrap();
            let marker = runtime.path().join(marker_name(&scope).unwrap());
            std::fs::write(&marker, "00000000000000000000000000000001\n").unwrap();
            let limits = dev_tools_privilege_session::GrantLimits::from_administrator_policy(
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
            .unwrap();
            let mut lease = dev_tools_privilege_session::GrantLifecycle::with_use_limit(
                limits,
                Duration::ZERO,
                None,
            )
            .unwrap();
            assert!(
                owner.available(),
                "first privileged instruction must see available release phase"
            );
            assert!(owner.revocation_reason().is_none());
            assert!(marker.exists());
            controller.0.kill().unwrap();
            controller.0.wait().unwrap();
            assert!(
                !owner.available(),
                "native controller death must immediately deny admission"
            );
            lease.stop(owner.revocation_reason().unwrap());
            remove_marker_at(runtime.path(), &scope).unwrap();
            assert_ne!(lease.state(), LeaseState::Active);
            assert!(
                !marker.exists(),
                "uncommitted user routing must be withdrawn"
            );
        }
    }

    #[test]
    fn startup_activation_requires_exact_typed_descriptor_handoff() {
        let grant = "0123456789abcdef0123456789abcdef".to_owned();
        for bootstrap in [false, true] {
            let request = ControlRequest::ActivateLaunch {
                grant: grant.clone(),
                bootstrap,
            };
            for count in 0..=4 {
                assert_eq!(
                    request_descriptors_valid(&request, count),
                    count == if bootstrap { 3 } else { 0 }
                );
            }
        }
        assert!(!request_descriptors_valid(&ControlRequest::Status, 2));
    }

    #[test]
    fn capped_plan_cannot_be_reinterpreted_as_direct_argv_or_native_sudo() {
        let mut policy = Policy::template();
        policy.operations.insert(
            "capped".into(),
            super::super::policy::ExecutionPlan {
                nodes: vec![super::super::policy::PlanCommand {
                    program: "/usr/bin/true".into(),
                    arguments: vec![],
                    working_directory: "/".into(),
                    environment: vec![],
                    run_as: None,
                    stdin: None,
                    stdout: None,
                    stderr: None,
                    after: vec![],
                }],
                pipes: vec![],
                exit_policy: super::super::policy::ExitPolicy::Last,
                output_limit_bytes: Some(32),
            },
        );
        let authority = Authority::Typed {
            operations: vec!["capped".into()],
        };
        let command = super::super::Execution {
            program: "/usr/bin/true".into(),
            arguments: vec![],
            working_directory: "/".into(),
            environment: vec![],
            terminal: false,
        };
        assert!(matches!(
            execution_authority(&policy, &authority, command.clone()),
            Err(Failure::AuthorityDenied)
        ));
        assert!(super::super::graph::select(&policy, &authority, &authority).is_ok());
        assert!(execution_authority(&policy, &Authority::Administrator, command).is_ok());

        let mut uncapped = policy.operations["capped"].clone();
        uncapped.output_limit_bytes = None;
        let requested = super::super::Execution {
            program: "/usr/bin/true".into(),
            arguments: vec![],
            working_directory: "/".into(),
            environment: vec![],
            terminal: false,
        };
        policy.operations.insert("capped".into(), uncapped.clone());
        assert!(execution_authority(&policy, &authority, requested.clone()).is_ok());
        for field in ["run_as", "stdin", "stdout", "stderr"] {
            let mut selected = uncapped.clone();
            let node = &mut selected.nodes[0];
            match field {
                "run_as" => {
                    node.run_as = Some(super::super::policy::RunAsIdentity {
                        uid: 0,
                        gid: 0,
                        supplementary_groups: vec![],
                    });
                }
                "stdin" => node.stdin = Some(super::super::policy::PlanStreamMode::Null),
                "stdout" => node.stdout = Some(super::super::policy::PlanStreamMode::Inherit),
                "stderr" => node.stderr = Some(super::super::policy::PlanStreamMode::Null),
                _ => unreachable!(),
            }
            let digest = selected.digest().unwrap();
            policy.operations.insert("capped".into(), selected.clone());
            policy.plans.insert(digest.clone(), selected);
            for selected_authority in [authority.clone(), Authority::ExactPlan { sha256: digest }] {
                assert!(matches!(
                    execution_authority(&policy, &selected_authority, requested.clone()),
                    Err(Failure::AuthorityDenied)
                ));
                assert!(super::super::graph::select(
                    &policy,
                    &selected_authority,
                    &selected_authority
                )
                .is_ok());
            }
        }
    }

    #[test]
    fn prepaid_relay_admission_is_exact_to_the_owned_child_and_consumed_once() {
        for initial in [
            RelayAdmission::Ordinary,
            RelayAdmission::Preparing,
            RelayAdmission::Claimed,
        ] {
            let mut relay = initial;
            assert_eq!(relay.claim(123), Err(Failure::AuthorityDenied));
            assert_eq!(relay, initial);
        }
        let mut relay = RelayAdmission::Ready(123);
        assert_eq!(relay.claim(124), Err(Failure::AuthorityDenied));
        assert!(relay.may_claim(123));
        relay.claim(123).unwrap();
        assert!(!relay.may_claim(123));
        assert_eq!(relay.claim(123), Err(Failure::AuthorityDenied));
    }

    #[test]
    fn operation_failure_preserves_established_or_uncertain_progress() {
        let failure = || Err(Failure::CleanupFailed);
        let result = Progress::default().finish("revoke", failure());
        assert_eq!(result.changed, Some(false));
        let mut progress = Progress::default();
        progress.entered();
        assert_eq!(progress.finish("leave", failure()).changed, None);
        let mut progress = Progress::default();
        progress.changed();
        progress.entered();
        let result = progress.finish("exec", failure());
        assert_eq!(result.changed, Some(true));
        assert_eq!(result.error_kind, Some(Failure::CleanupFailed));
    }

    #[test]
    fn missing_ambiguous_or_unreadable_population_is_authority_loss() {
        assert_eq!(parse_population(b"populated 0\nfrozen 0\n"), Ok(true));
        assert_eq!(parse_population(b"populated 1\n"), Ok(false));
        for bytes in [
            b"".as_slice(),
            b"populated 0\npopulated 1\n",
            b"populated 2\n",
            b"populated \xff\n",
        ] {
            assert_eq!(parse_population(bytes), Err(Failure::NativeUnavailable));
        }
    }

    #[test]
    fn stale_routing_names_cannot_claim_foreign_or_ambiguous_native_identity() {
        for scope in [
            NativeScope {
                account: Account::Unix { uid: 1000 },
                workload: None,
            },
            NativeScope {
                account: Account::Unix { uid: 1000 },
                workload: Some(123),
            },
        ] {
            assert_eq!(
                parse_marker_name(&marker_name(&scope).unwrap()).unwrap(),
                scope
            );
        }
        for name in [
            "user-0",
            "user-01000",
            "user-+1000",
            "user-1000/../escape",
            "workload-1000-1",
            "workload-1000-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "admin-1000",
        ] {
            assert!(parse_marker_name(name).is_err(), "{name}");
        }
    }
}
