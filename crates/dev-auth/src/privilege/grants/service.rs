use super::model::{Envelope, FRAME_LIMIT, WIRE_SCHEMA};
use super::native::{self, Caller, Look, Unobserved};
use super::policy::{Account, NativeScope, Policy};
use super::{
    Authority, ControlRequest, ControlResult, Failure, Grant, GrantRequest, GrantRequirement,
    GrantScope, GrantState,
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

mod command;
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
        self.presence() == Ok(true)
    }

    fn available(&self) -> bool {
        self.phase != LaunchPhase::Pending
            && self.present()
            && self
                .release_deadline
                .is_some_and(|deadline| now().is_ok_and(|observed| observed < deadline))
    }

    /// One look at whether the retained native owner is still the same live
    /// process, in its registered cgroup, running the installed image.
    fn presence(&self) -> Look<bool> {
        if native::readable(&self.pidfd)? {
            return Ok(false);
        }
        let Some(cgroup) = native::cgroup_look(self.pid)? else {
            return Ok(false);
        };
        let Some(image) = native::process_look(File::open(format!("/proc/{}/exe", self.pid)))?
        else {
            return Ok(false);
        };
        Ok(cgroup == self.native_cgroup && native::identical(&image, &self.image)?)
    }

    fn release_expired(&self) -> bool {
        self.release_deadline
            .is_some_and(|deadline| !now().is_ok_and(|observed| observed < deadline))
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
    /// The pidfd of each command-scoped grant's program, whose exit ends that
    /// grant (ADR 0139).
    commands: BTreeMap<GrantId, OwnedFd>,
    phase: Phase,
    unseen: Unseen,
}

/// Whether the coordinator admits new managed work (ADR 0138, ADR 0141).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Serving,
    /// Nothing new is admitted, and running jobs finish under their grants.
    Draining(Drain),
    /// Shutdown stopped every grant.
    Stopping,
}

/// Why a coordinator drains, which decides when the drain ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drain {
    /// A watched trust input changed. The drain ends once no managed job or
    /// connection remains, and the coordinator then exits so the service
    /// manager starts one that binds the new state.
    Changed(Input),
    /// The service manager asked the coordinator to stop. The drain ends
    /// once no managed job remains, or at boot time `until`.
    Stop { until: Duration },
}

/// Why the coordinator stops serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Stopped,
    Changed(Input),
}

impl Phase {
    /// The phase once the service manager asks the coordinator to stop at
    /// boot time `now`.
    fn stop_requested(self, _now: Duration) -> Self {
        Self::Stopping
    }

    /// Why a coordinator in this phase stops serving at boot time `now`, with
    /// `running_jobs` managed jobs, `active_grants` active grants and, when
    /// `connections_idle`, no open connection.
    fn drained(
        self,
        running_jobs: usize,
        _active_grants: usize,
        connections_idle: bool,
        now: Duration,
    ) -> Option<Exit> {
        match self {
            Self::Draining(Drain::Changed(input)) if running_jobs == 0 && connections_idle => {
                Some(Exit::Changed(input))
            }
            Self::Draining(Drain::Stop { until }) if running_jobs == 0 || now >= until => {
                Some(Exit::Stopped)
            }
            Self::Stopping => Some(Exit::Stopped),
            Self::Serving | Self::Draining(_) => None,
        }
    }
}

/// What a supervision look was about, for its journal lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Subject {
    Trust,
    Workload(GrantId),
    LaunchOwner(GrantId),
    Cleanup(GrantId),
    Client(GrantId),
}

impl std::fmt::Display for Subject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trust => formatter.write_str("the watched trust inputs"),
            Self::Workload(id) => write!(formatter, "the workload of grant={id:032x}"),
            Self::LaunchOwner(id) => write!(formatter, "the launch owner of grant={id:032x}"),
            Self::Cleanup(id) => write!(formatter, "the boundary of stopping grant={id:032x}"),
            Self::Client(id) => write!(formatter, "the client of job={id:032x}"),
        }
    }
}

/// Subjects whose last look could not be taken, so a lasting fault writes one
/// journal line when it starts and one when it clears.
#[derive(Default)]
struct Unseen(BTreeSet<Subject>);

impl Unseen {
    fn note<T>(&mut self, subject: Subject, look: &Look<T>) {
        match look {
            Err(Unobserved(kind)) if self.0.insert(subject) => {
                eprintln!("dev-auth could not observe {subject}: {kind:?}; retrying");
            }
            Ok(_) if self.0.remove(&subject) => eprintln!("dev-auth observes {subject} again"),
            _ => {}
        }
    }
}

struct PendingRelay {
    caller: Caller,
    grant: GrantId,
    expires: Duration,
}

struct Service {
    policy: Policy,
    policy_source: Bound,
    parent: File,
    runtime: PathBuf,
    coordinator: OwnedFd,
    sudo: Bound,
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
    clear_markers(&configuration.runtime)?;
    let policy_source = Bound::open(Input::Policy, &configuration.policy)?;
    let mut bytes = Vec::new();
    policy_source
        .file
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
    let sudo = bind_sudo(&policy)?;
    if FileStamp::of(&policy_source.file)? != policy_source.stamp {
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
    runtime.block_on(verify_unit(
        || verify_service_unit(&parent_path),
        UNIT_VERIFICATION,
    ))?;
    // Systemd owns crash cleanup of the entire unit. Do not accept requests
    // until all owned remnants are gone and their cleanup is proven.
    recover_cgroups(&parent)?;
    let listener = create_listener(&configuration.runtime.join("control.sock"))?;
    let sudo_listener = create_listener(&configuration.runtime.join("sudo.sock"))?;
    let service = Arc::new(Service {
        policy,
        policy_source,
        parent,
        runtime: configuration.runtime,
        coordinator,
        sudo,
        product_file,
        state: Mutex::new(State {
            registry: GrantRegistry::new(MAX_GRANTS).map_err(|_| Failure::RuntimeFailure)?,
            metadata: BTreeMap::new(),
            selected: BTreeMap::new(),
            jobs: BTreeMap::new(),
            pending_relays: BTreeMap::new(),
            commands: BTreeMap::new(),
            phase: Phase::Serving,
            unseen: Unseen::default(),
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
    let exit = loop {
        tokio::select! {
            biased;
            _ = terminate.recv() => {
                if let Some(exit) = request_stop(&service, connections.is_empty()).await { break exit; }
            }
            _ = interrupt.recv() => {
                if let Some(exit) = request_stop(&service, connections.is_empty()).await { break exit; }
            }
            readiness = timer.readable() => {
                let mut readiness = readiness.map_err(|_| Failure::NativeUnavailable)?;
                let mut bytes = [0_u8; 8];
                let _ = readiness.try_io(|fd| nix::unistd::read(fd.get_ref(), &mut bytes).map_err(io::Error::from));
                reap(&service).await.map_err(integrity_lost)?;
                {
                    let state = service.state.lock().await;
                    let observed = self::now().map_err(|_| integrity_lost(Integrity::Clock))?;
                    if let Some(exit) = state.phase.drained(state.jobs.len(), active_grants(&state), connections.is_empty(), observed) {
                        break exit;
                    }
                }
                login_tick += 1;
                if login_tick >= 10 {
                    login_tick = 0;
                    if login_check.as_ref().is_none_or(tokio::task::JoinHandle::is_finished) {
                        if let Some(finished) = login_check.take() {
                            if finished.await.is_err() { break Exit::Stopped; }
                        }
                        let service = Arc::clone(&service);
                        login_check = Some(tokio::spawn(async move { check_logins(&service).await; }));
                    }
                }
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) { break Exit::Stopped; }
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
    };
    if let Exit::Changed(input) = exit {
        eprintln!(
            "dev-auth grant coordinator exiting: the {input} changed and no managed job remains; the service manager starts a coordinator that binds the new state"
        );
    }
    {
        let mut state = service.state.lock().await;
        state.phase = Phase::Stopping;
        state.registry.stop_all(StopReason::BrokerShutdown, now()?);
    }
    for _ in 0..50 {
        reap(&service).await.map_err(integrity_lost)?;
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
    finish_connections(&mut connections, CONNECTION_SETTLE).await;
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
    match exit {
        Exit::Changed(_) => Err(Failure::AuthorityDenied),
        Exit::Stopped => Ok(()),
    }
}

/// How long a stopping coordinator lets its connections deliver their
/// results once every grant has ended (ADR 0141).
const CONNECTION_SETTLE: Duration = Duration::from_secs(5);

/// Apply the service manager's stop request, and report whether the
/// coordinator stops serving at once.
async fn request_stop(service: &Service, connections_idle: bool) -> Option<Exit> {
    let mut state = service.state.lock().await;
    let Ok(observed) = now() else {
        return Some(Exit::Stopped);
    };
    state.phase = state.phase.stop_requested(observed);
    state.phase.drained(
        state.jobs.len(),
        active_grants(&state),
        connections_idle,
        observed,
    )
}

fn active_grants(state: &State) -> usize {
    state
        .registry
        .iter()
        .filter(|grant| grant.lifetime.state() == LeaseState::Active)
        .count()
}

/// Let connection tasks finish delivering their results for at most
/// `budget`, then cancel the rest.
async fn finish_connections(connections: &mut tokio::task::JoinSet<()>, _budget: Duration) {
    connections.abort_all();
    while connections.join_next().await.is_some() {}
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
        ControlRequest::Run { .. } => count == 5,
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
    if admits_new_work(&request) {
        let phase = service.state.lock().await.phase;
        let admitted = if uses_existing_grant(&request) {
            service.grant_use(phase).admits()
        } else {
            admission(phase, service.trust())
        };
        if let Err(failure) = admitted {
            return ControlResult::failure(operation, failure, Some(false));
        }
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
        ControlRequest::Run {
            authority,
            duration_seconds,
            executable,
            execution,
        } => {
            command::run(
                service,
                &caller,
                command::Requested {
                    request: GrantRequest::command(authority, duration_seconds),
                    executable,
                    execution,
                },
                streams,
                connection,
                &mut progress,
            )
            .await
        }
        ControlRequest::Status { requirement } => {
            observe(service, &caller, None, requirement).await
        }
        ControlRequest::Inspect { grant } => observe(service, &caller, Some(&grant), None).await,
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
    let boundaries = state
        .jobs
        .iter()
        .map(|(id, job)| (*id, job.boundary.directory()));
    if let Some(job) = job_in_cgroup(boundaries, &directory)?.and_then(|id| state.jobs.get(&id)) {
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
    }
    Ok(())
}

/// The job whose boundary is exactly the caller's cgroup. The kernel identity
/// of the cgroup directory is the only selector; a path, PID or grant ID that
/// a caller names never selects a job.
fn job_in_cgroup<'a>(
    boundaries: impl IntoIterator<Item = (GrantId, &'a File)>,
    cgroup: &File,
) -> Result<Option<GrantId>, Failure> {
    for (id, boundary) in boundaries {
        if native::same_file(cgroup, boundary)? {
            return Ok(Some(id));
        }
    }
    Ok(None)
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
        if state.phase != Phase::Serving
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
    let approval =
        super::approval::approve(caller, &request, &format!("{id:032x}"), control, None).await;
    let mut state = service.state.lock().await;
    drop(pending);
    approval?;
    let _setup = setup_admission(service)?;
    if admission(state.phase, service.trust()).is_err()
        || !caller.still_present()
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
    if admission(state.phase, service.trust()).is_err()
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
    withdraw_uncommitted_launch(service, state, id)
}

fn withdraw_uncommitted_launch(
    service: &Service,
    state: &mut State,
    id: GrantId,
) -> Result<(), Failure> {
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
) -> Result<(), Integrity> {
    state.registry.poll(now);
    let mut abandoned = Vec::new();
    let mut looks = Vec::new();
    for (id, metadata) in &state.metadata {
        let Some(owner) = &metadata.launch_owner else {
            continue;
        };
        let presence = owner.presence();
        if launch_revocation(presence, owner.release_expired()).is_some()
            || state
                .registry
                .get(*id)
                .is_none_or(|grant| grant.lifetime.state() != LeaseState::Active)
        {
            abandoned.push(*id);
        }
        looks.push((Subject::LaunchOwner(*id), presence));
    }
    for (subject, presence) in looks {
        state.unseen.note(subject, &presence);
    }
    for id in abandoned {
        state
            .registry
            .stop(id, StopReason::WorkloadEnded, now)
            .map_err(|_| Integrity::RecordsDisagree(id))?;
        // The stopped grant admits nothing. A failed withdrawal keeps the
        // launch owner, so the next sweep retries it.
        if let Err(failure) = withdraw_uncommitted_launch(service, state, id) {
            eprintln!(
                "dev-auth abandoned launch withdrawal failed: grant={id:032x} failure={failure:?}; retrying"
            );
        }
    }
    Ok(())
}

async fn sweep_abandoned_launches(service: &Service) -> Result<(), Failure> {
    let mut state = service.state.lock().await;
    sweep_abandoned_launches_locked(service, &mut state, now()?).map_err(Failure::from)
}

async fn observe(
    service: &Service,
    caller: &Caller,
    selected: Option<&str>,
    requirement: Option<GrantRequirement>,
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
    if let Some(requirement) = requirement {
        let scope_of = |id: GrantId| {
            state
                .metadata
                .get(&id)
                .map(|metadata| metadata.request.scope)
        };
        match covering(&state, &caller.scope, requirement.scope, scope_of) {
            Ok(id) => {
                let grant = snapshot(&state, id, now)?;
                if !requirement.met_by(&grant) {
                    response.error_kind = Some(Failure::InsufficientRemaining);
                }
                response.grant = Some(grant);
            }
            Err(failure) => response.error_kind = Some(failure),
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
            match select(&state, &caller.scope, None) {
                Err(Failure::NoGrant) if leave => {
                    return Ok(ControlResult::success("leave", false));
                }
                selected => selected?,
            }
        };
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
    if state.phase != Phase::Serving {
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
        if state.phase != Phase::Serving || state.jobs.len() >= MAX_EXECUTIONS {
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
            user_session: None,
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
    let sent = send_started(connection, hard_deadline, terminal, master);
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
                .sudo
                .file
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
    let status = wait_leader(
        service,
        caller,
        connection,
        &events,
        (job_id, grant_id),
        hard_deadline,
        &child,
    )
    .await?;
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
                    .map_or(Ok(true), |job| job.boundary.is_empty())
                    .unwrap_or(false)
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

/// Tell the client that its execution starts, handing it the terminal relay's
/// master end when there is one.
fn send_started(
    connection: &OwnedFd,
    hard_deadline: Duration,
    terminal: bool,
    master: Option<OwnedFd>,
) -> Result<(), Failure> {
    let started = super::execution_io::Started {
        schema: super::execution_io::START_SCHEMA.to_owned(),
        hard_deadline_milliseconds: u64::try_from(hard_deadline.as_millis())
            .map_err(|_| Failure::InvalidRequest)?,
        terminal,
    };
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
}

/// Wait for one directly spawned job leader to exit while relaying the
/// client's signals and the leader's job-control stops.
async fn wait_leader(
    service: &Service,
    caller: &Caller,
    connection: &OwnedFd,
    events: &OwnedFd,
    (job_id, grant_id): (GrantId, GrantId),
    hard_deadline: Duration,
    child: &std::process::Child,
) -> Result<std::process::ExitStatus, Failure> {
    let mut unseen = Unseen::default();
    loop {
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
        let presence = caller.presence();
        unseen.note(Subject::Client(job_id), &presence);
        if client_left(presence, native::readable(connection)) {
            let mut state = service.state.lock().await;
            if let Some(job) = state.jobs.get_mut(&job_id) {
                let _ = job.boundary.stop();
            }
        }
        match super::execution_io::receive_signal(events) {
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
            Ok(WaitStatus::Exited(_, code)) => {
                return Ok(std::process::ExitStatus::from_raw(code << 8))
            }
            Ok(WaitStatus::Signaled(_, signal, core)) => {
                return Ok(std::process::ExitStatus::from_raw(
                    signal as i32 | if core { 0x80 } else { 0 },
                ))
            }
            Ok(WaitStatus::Stopped(_, signal)) => {
                if super::execution_io::report_stopped(events, signal).is_err() {
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
    }
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
    let mut unseen = Unseen::default();
    loop {
        let expired = !self::now().is_ok_and(|now| now < hard_deadline);
        let presence = caller.presence();
        unseen.note(Subject::Client(job_id), &presence);
        let disconnected = client_left(presence, native::readable(connection));
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
        let empty = joined && job.boundary.is_empty().unwrap_or(false);
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
    if native::readable(&captured.connection) == Ok(true) {
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

/// The only faults that end a reaping pass, and with it the coordinator
/// (ADR 0137). A failure that belongs to one grant stays with that grant.
#[derive(Clone, Copy)]
enum Integrity {
    Clock,
    RecordsDisagree(GrantId),
}

impl std::fmt::Display for Integrity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clock => formatter.write_str("the boot clock is unreadable"),
            Self::RecordsDisagree(id) => {
                write!(formatter, "the records of grant={id:032x} disagree")
            }
        }
    }
}

impl From<Integrity> for Failure {
    fn from(_: Integrity) -> Self {
        Self::RuntimeFailure
    }
}

fn integrity_lost(integrity: Integrity) -> Failure {
    eprintln!("dev-auth grant coordinator exiting: {integrity}");
    integrity.into()
}

async fn reap(service: &Service) -> Result<(), Integrity> {
    let now = now().map_err(|_| Integrity::Clock)?;
    let mut state = service.state.lock().await;
    state.pending_relays.retain(|_, pending| {
        now < pending.expires && native::alive(pending.caller.peer.peer_pidfd())
    });
    if state.phase == Phase::Serving {
        let look = service.trust();
        watch_trust(&mut state, look);
    }
    let workloads: Vec<_> = state
        .metadata
        .iter()
        .filter_map(|(id, metadata)| {
            metadata
                .workload
                .as_ref()
                .map(|workload| (*id, population(workload)))
        })
        .collect();
    for (id, population) in workloads {
        state.unseen.note(Subject::Workload(id), &population);
        if let Some(reason) = workload_end(population) {
            state
                .registry
                .stop(id, reason, now)
                .map_err(|_| Integrity::RecordsDisagree(id))?;
        }
    }
    command::end_exited(&mut state, now)?;
    sweep_abandoned_launches_locked(service, &mut state, now)?;
    state.registry.poll(now);
    withdraw_ended_routing(&service.runtime, &mut state);
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
            .is_some_and(|leader| native::readable(leader) == Ok(true))
        {
            // ADR 0136: a command that native sudo started outlives sudo
            // within its grant. Only an invocation that never attached, and so
            // never started its command, is stopped when sudo exits.
            if job.preparing {
                let _ = job.boundary.stop();
            }
            job.leader_done = true;
            job.preparing = false;
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
        let metadata = state
            .metadata
            .get_mut(&id)
            .ok_or(Integrity::RecordsDisagree(id))?;
        let population = metadata
            .boundary
            .is_empty()
            .map_err(|error| Unobserved(error.kind()));
        if population == Ok(true) {
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
        state.unseen.note(Subject::Cleanup(id), &population);
    }
    let terminal: Vec<_> = state
        .registry
        .iter()
        .filter(|grant| grant.lifetime.state().is_terminal())
        .map(|grant| (grant.id, grant.lifetime.state()))
        .collect();
    for (id, lease) in terminal {
        let metadata = state
            .metadata
            .get_mut(&id)
            .ok_or(Integrity::RecordsDisagree(id))?;
        if metadata.terminal_since.is_none() {
            eprintln!("dev-auth grant ended: grant={id:032x} lease={lease:?}");
            metadata.terminal_since = Some(now);
        }
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
            state.commands.remove(&id);
        }
    }
    let State {
        metadata, unseen, ..
    } = &mut *state;
    unseen.0.retain(|subject| match subject {
        Subject::Workload(id) | Subject::LaunchOwner(id) | Subject::Cleanup(id) => {
            metadata.contains_key(id)
        }
        Subject::Trust | Subject::Client(_) => true,
    });
    Ok(())
}

async fn check_logins(service: &Service) {
    let accounts: BTreeSet<_> = service
        .state
        .lock()
        .await
        .metadata
        .values()
        .filter(|metadata| metadata.request.scope.ends_at_logout())
        .map(|metadata| metadata.scope.account.clone())
        .collect();
    for account in accounts {
        let Account::Unix { uid } = account else {
            continue;
        };
        let observation = tokio::time::timeout(
            Duration::from_secs(2),
            super::approval::account_has_login(uid),
        )
        .await
        .unwrap_or(Err(Failure::NativeUnavailable));
        if let Err(failure) = observation {
            eprintln!(
                "dev-auth login observation failed: uid={uid} failure={failure:?}; user grants continue"
            );
        }
        if login_ended(observation) {
            let mut state = service.state.lock().await;
            let ids: Vec<_> = state
                .metadata
                .iter()
                .filter(|(_, metadata)| {
                    metadata.scope.account == account && metadata.request.scope.ends_at_logout()
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

/// Whether one native login observation ends the account's user-scope grants.
/// Only logind's positive answer that no interactive session remains is a
/// logout; an unavailable or failing query is retried on the next pass.
fn login_ended(observation: Result<bool, Failure>) -> bool {
    observation == Ok(false)
}

fn requested_scope(caller: &Caller, scope: GrantScope) -> Result<NativeScope, Failure> {
    match scope {
        GrantScope::User => Ok(NativeScope {
            account: caller.scope.account.clone(),
            workload: None,
        }),
        // A caller in a command grant's boundary has a keyed scope but no
        // workload; a workload grant cannot relabel that boundary.
        GrantScope::Workload if caller.workload.is_some() => Ok(caller.scope.clone()),
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
        routing_candidates(scope)
            .iter()
            .find_map(|candidate| routed(state, candidate))
            .ok_or(Failure::NoGrant)?
    };
    usable(state, id)
}

/// The grant a remaining-time requirement checks: the one `select` routes for
/// this caller now, or with a scope, the caller's routable grant of that
/// scope (ADR 0139).
fn covering(
    state: &State,
    scope: &NativeScope,
    kind: Option<GrantScope>,
    scope_of: impl Fn(GrantId) -> Option<GrantScope>,
) -> Result<GrantId, Failure> {
    let id = routing_candidates(scope)
        .iter()
        .filter_map(|candidate| routed(state, candidate))
        .find(|id| kind.is_none_or(|kind| scope_of(*id) == Some(kind)))
        .ok_or(Failure::NoGrant)?;
    usable(state, id)
}

/// The scopes whose selected grant routes a caller, in order: the caller's
/// own boundary, then its account (ADR 0136).
fn routing_candidates(scope: &NativeScope) -> [NativeScope; 2] {
    [
        scope.clone(),
        NativeScope {
            account: scope.account.clone(),
            workload: None,
        },
    ]
}

fn routed(state: &State, candidate: &NativeScope) -> Option<GrantId> {
    state
        .selected
        .get(candidate)
        .copied()
        .filter(|id| routes(&state.registry, *id))
}

/// A grant whose own or an ancestor's pending launch owner is unavailable
/// admits nothing.
fn usable(state: &State, id: GrantId) -> Result<GrantId, Failure> {
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

/// Sudo routing lives exactly as long as its grant is active (ADR 0136).
fn routes(registry: &GrantRegistry<NativeScope, Authority>, id: GrantId) -> bool {
    registry
        .get(id)
        .is_some_and(|grant| grant.lifetime.state() == LeaseState::Active)
}

/// Withdraw every published marker whose grant no longer routes sudo. A
/// failed removal keeps its selection, which `select` already ignores, so the
/// next pass retries it.
fn withdraw_ended_routing(runtime: &Path, state: &mut State) {
    let ended: Vec<_> = state
        .selected
        .iter()
        .filter(|(_, id)| !routes(&state.registry, **id))
        .map(|(scope, id)| (scope.clone(), *id))
        .collect();
    for (scope, id) in ended {
        let lease = state.registry.get(id).map(|grant| grant.lifetime.state());
        match remove_marker_at(runtime, &scope) {
            Ok(()) => {
                state.selected.remove(&scope);
                eprintln!("dev-auth grant routing withdrawn: grant={id:032x} lease={lease:?}");
            }
            Err(failure) => {
                eprintln!(
                    "dev-auth grant routing withdrawal failed: grant={id:032x} failure={failure:?}"
                );
            }
        }
    }
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

/// A trust input the coordinator binds at startup (ADR 0115). Admission needs
/// each one unchanged, and a change drains the coordinator (ADR 0138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Input {
    Policy,
    SudoProgram,
}

impl std::fmt::Display for Input {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Policy => "grant policy",
            Self::SudoProgram => "sudo program",
        })
    }
}

/// A trust input bound at startup: its path, the file that path named then,
/// held open, and that file's stamp.
struct Bound {
    input: Input,
    path: PathBuf,
    file: File,
    stamp: FileStamp,
}

impl Bound {
    fn open(input: Input, path: &Path) -> Result<Self, Failure> {
        let file = root_file(path, false)?;
        Ok(Self {
            input,
            path: path.to_owned(),
            stamp: FileStamp::of(&file)?,
            file,
        })
    }

    /// Whether the file the path names now is still the one bound at startup.
    fn look(&self) -> Look<bool> {
        let named = protected_file(&self.path, false)
            .and_then(|file| file.as_ref().map(FileStamp::look).transpose());
        unchanged(self.stamp, FileStamp::look(&self.file), named)
    }
}

impl Service {
    /// The first watched trust input a look finds changed. A look that could
    /// not be taken is not a change.
    fn trust(&self) -> Look<Option<Input>> {
        changed_input([&self.policy_source, &self.sudo].map(|bound| (bound.input, bound.look())))
    }
}

/// Whether a bound input still names the file the coordinator trusted, from
/// the stamp of the descriptor held since startup and the stamp of the file
/// its path names now, which is `None` when the path names no protected file.
fn unchanged(
    bound: FileStamp,
    held: Look<FileStamp>,
    named: Look<Option<FileStamp>>,
) -> Look<bool> {
    let observed_change =
        held.is_ok_and(|held| held != bound) || named.is_ok_and(|named| named != Some(bound));
    if observed_change {
        return Ok(false);
    }
    held.and(named).map(|_| true)
}

fn changed_input<const N: usize>(looks: [(Input, Look<bool>); N]) -> Look<Option<Input>> {
    let mut unobserved = None;
    for (input, look) in looks {
        match look {
            Ok(true) => {}
            Ok(false) => return Ok(Some(input)),
            Err(failure) => unobserved = unobserved.or(Some(failure)),
        }
    }
    unobserved.map_or(Ok(None), Err)
}

/// Admission needs a serving coordinator and a fresh look that finds every
/// watched trust input unchanged. A look that could not be taken refuses only
/// this admission.
fn admission(phase: Phase, trust: Look<Option<Input>>) -> Result<(), Failure> {
    match (phase, trust) {
        (Phase::Serving, Ok(None)) => Ok(()),
        (Phase::Serving, Err(_)) => Err(Failure::NativeUnavailable),
        (Phase::Serving, Ok(Some(_))) | (Phase::Draining(_), _) => Err(Failure::AuthorityDenied),
        (Phase::Stopping, _) => Err(Failure::Busy),
    }
}

/// Apply one look at the watched trust inputs. A change closes admission for
/// good and leaves every grant and job running; a look that could not be
/// taken changes nothing.
fn watch_trust(state: &mut State, look: Look<Option<Input>>) {
    state.unseen.note(Subject::Trust, &look);
    if let (Phase::Serving, Ok(Some(input))) = (state.phase, look) {
        state.phase = Phase::Draining(Drain::Changed(input));
        eprintln!(
            "dev-auth grant trust changed: the {input} is not the one bound at startup; admission is closed and {} running job(s) continue under their grants",
            state.jobs.len()
        );
    }
}

/// Whether an admitted request runs new work under a grant that is already
/// active, and so follows `grant_use` instead of `admission` (ADR 0141).
fn uses_existing_grant(_request: &ControlRequest) -> bool {
    false
}

/// Whether a control request admits new managed work, and so needs the trust
/// the coordinator bound at startup. Observing and ending grants never does.
fn admits_new_work(request: &ControlRequest) -> bool {
    match request {
        ControlRequest::Status { .. }
        | ControlRequest::Inspect { .. }
        | ControlRequest::Revoke { .. }
        | ControlRequest::Leave => false,
        ControlRequest::Request { .. }
        | ControlRequest::Run { .. }
        | ControlRequest::LaunchRequest { .. }
        | ControlRequest::ActivateLaunch { .. }
        | ControlRequest::CommitLaunch { .. }
        | ControlRequest::Exec { .. }
        | ControlRequest::RunPlan { .. }
        | ControlRequest::SudoRelay { .. }
        | ControlRequest::Delegate { .. } => true,
    }
}

/// Bind the sudo program that `policy` names. Startup and every later
/// selection of a replaced program use this one validation (ADR 0141).
fn bind_sudo(policy: &Policy) -> Result<Bound, Failure> {
    Bound::open(Input::SudoProgram, Path::new(&policy.sudo_program))
}

/// The sudo program that managed sudo admits through now (ADR 0141), from
/// one look at the program bound at startup.
fn current_sudo(
    look: Look<bool>,
    bound: &File,
    _rebind: impl FnOnce() -> Result<File, Failure>,
) -> Result<File, Failure> {
    match look {
        Ok(true) => bound.try_clone().map_err(|_| Failure::NativeUnavailable),
        Ok(false) => Err(Failure::AuthorityDenied),
        Err(_) => Err(Failure::NativeUnavailable),
    }
}

impl Service {
    fn sudo_program(&self) -> Result<File, Failure> {
        current_sudo(self.sudo.look(), &self.sudo.file, || {
            bind_sudo(&self.policy).map(|bound| bound.file)
        })
    }

    /// Admission of new work under an active grant now, from a fresh look at
    /// the grant policy.
    fn grant_use(&self, phase: Phase) -> GrantUse {
        grant_use(phase, self.policy_source.look())
    }
}

/// Whether new work runs under a grant that is already active (ADR 0141):
/// managed sudo, a sudo relay, `exec` or `run-plan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantUse {
    Open,
    /// The coordinator drains and refuses new work under every grant.
    Draining,
    /// The grant policy could not be observed, which refuses this admission.
    Unobserved,
}

impl GrantUse {
    fn admits(self) -> Result<(), Failure> {
        match self {
            Self::Open => Ok(()),
            Self::Draining => Err(Failure::AuthorityDenied),
            Self::Unobserved => Err(Failure::NativeUnavailable),
        }
    }
}

/// Admission of new work under an active grant in `phase`, from one look at
/// whether the grant policy is unchanged.
fn grant_use(phase: Phase, policy: Look<bool>) -> GrantUse {
    match (phase, policy) {
        (Phase::Serving, Ok(true)) => GrantUse::Open,
        (Phase::Serving, Err(_)) => GrantUse::Unobserved,
        _ => GrantUse::Draining,
    }
}

/// How the bridge answers a sudo preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preflight {
    Native,
    Admit(GrantId),
    Draining,
}

/// The preflight answer for an invocation whose grant `selection` found,
/// under `admission` (ADR 0141).
fn preflight_answer(
    selection: Result<GrantId, Failure>,
    admission: GrantUse,
) -> Result<Preflight, Failure> {
    match selection {
        Err(Failure::NoGrant) => Ok(Preflight::Native),
        Err(failure) => Err(failure),
        Ok(id) => match admission {
            GrantUse::Open => Ok(Preflight::Admit(id)),
            GrantUse::Draining => Err(Failure::AuthorityDenied),
            GrantUse::Unobserved => Err(Failure::NativeUnavailable),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        Self::look(file).map_err(|_| Failure::AuthorityDenied)
    }

    fn look(file: &File) -> Look<Self> {
        let metadata = file.metadata().map_err(|error| Unobserved(error.kind()))?;
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
    protected_file(path, directory)
        .ok()
        .flatten()
        .ok_or(Failure::AuthorityDenied)
}

/// One look at the root-owned file a path names. `None` when the path or an
/// ancestor observably breaks root custody: a symlink, a wrong file type, or
/// a group- or world-writable or non-root owner.
fn protected_file(path: &Path, directory: bool) -> Look<Option<File>> {
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Ok(None);
    }
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| opening(&error))?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Ok(None);
        }
    }
    let Some(file) = opened(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                nix::libc::O_CLOEXEC
                    | nix::libc::O_NOFOLLOW
                    | if directory { nix::libc::O_DIRECTORY } else { 0 },
            )
            .open(path),
    )?
    else {
        return Ok(None);
    };
    let metadata = file.metadata().map_err(|error| opening(&error))?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Ok(None);
    }
    Ok(Some(file))
}

/// One no-follow open of a protected path: `None` when its final component
/// is a symlink or the wrong file type.
fn opened(open: io::Result<File>) -> Look<Option<File>> {
    match open {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(nix::libc::ELOOP | nix::libc::ENOTDIR)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(opening(&error)),
    }
}

/// A path that could not be opened or inspected now, including one absent
/// while it is replaced, has not been observed.
fn opening(error: &io::Error) -> Unobserved {
    Unobserved(error.kind())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitFault {
    Unreachable,
    Mismatch,
}

/// A failed call means the service manager has not answered yet only when
/// the bus could not deliver it. Any other reply is the manager's answer.
fn bus_fault(error: &zbus::Error) -> UnitFault {
    match error {
        zbus::Error::InputOutput(_) | zbus::Error::Connection(..) | zbus::Error::Handshake(_) => {
            UnitFault::Unreachable
        }
        zbus::Error::MethodError(name, _, _) => reply_fault(name.as_str()),
        zbus::Error::FDO(error) => fdo_fault(error),
        _ => UnitFault::Mismatch,
    }
}

fn fdo_fault(error: &zbus::fdo::Error) -> UnitFault {
    match error {
        zbus::fdo::Error::ZBus(error) => bus_fault(error),
        error => reply_fault(zbus::DBusError::name(error).as_str()),
    }
}

fn reply_fault(name: &str) -> UnitFault {
    match name.strip_prefix("org.freedesktop.DBus.Error.") {
        Some(
            "ServiceUnknown" | "NameHasNoOwner" | "NoReply" | "Timeout" | "TimedOut"
            | "Disconnected" | "NoServer" | "IOError",
        ) => UnitFault::Unreachable,
        _ => UnitFault::Mismatch,
    }
}

#[derive(Clone, Copy)]
struct Backoff {
    attempt: Duration,
    first_delay: Duration,
    longest_delay: Duration,
    total: Duration,
}

const UNIT_VERIFICATION: Backoff = Backoff {
    attempt: Duration::from_secs(3),
    first_delay: Duration::from_millis(250),
    longest_delay: Duration::from_secs(5),
    total: Duration::from_secs(60),
};

async fn verify_unit<F, Attempt>(mut verify: F, backoff: Backoff) -> Result<(), Failure>
where
    F: FnMut() -> Attempt,
    Attempt: std::future::Future<Output = Result<(), UnitFault>>,
{
    let give_up = tokio::time::Instant::now() + backoff.total;
    let mut delay = backoff.first_delay;
    loop {
        let fault = match tokio::time::timeout(backoff.attempt, verify()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(fault)) => fault,
            Err(_) => UnitFault::Unreachable,
        };
        if fault == UnitFault::Mismatch {
            eprintln!("dev-auth grant service unit is not confirmed by the service manager");
            return Err(Failure::NativeUnavailable);
        }
        if tokio::time::Instant::now() + delay >= give_up {
            eprintln!(
                "dev-auth grant service unit unverified: the service manager did not answer within {:?}",
                backoff.total
            );
            return Err(Failure::NativeUnavailable);
        }
        eprintln!(
            "dev-auth grant service unit verification: the service manager did not answer; retrying in {delay:?}"
        );
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(backoff.longest_delay);
    }
}

async fn verify_service_unit(cgroup: &Path) -> Result<(), UnitFault> {
    use UnitFault::Mismatch;
    let connection = zbus::Connection::system()
        .await
        .map_err(|error| bus_fault(&error))?;
    let unit = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnitByPID",
            &(std::process::id(),),
        )
        .await
        .map_err(|error| bus_fault(&error))?;
    let unit: zbus::zvariant::OwnedObjectPath = unit.body().deserialize().map_err(|_| Mismatch)?;
    let properties = zbus::fdo::PropertiesProxy::builder(&connection)
        .destination("org.freedesktop.systemd1")
        .map_err(|_| Mismatch)?
        .path(unit)
        .map_err(|_| Mismatch)?
        .build()
        .await
        .map_err(|error| bus_fault(&error))?;
    let service_interface =
        zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Service")
            .map_err(|_| Mismatch)?;
    let main_pid = properties
        .get(service_interface.clone(), "MainPID")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let kill_mode = properties
        .get(service_interface.clone(), "KillMode")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let send_kill = properties
        .get(service_interface.clone(), "SendSIGKILL")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let group = properties
        .get(service_interface.clone(), "ControlGroup")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let exit_type = properties
        .get(service_interface.clone(), "ExitType")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let remain = properties
        .get(service_interface.clone(), "RemainAfterExit")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let delegated = properties
        .get(service_interface.clone(), "Delegate")
        .await
        .map_err(|error| fdo_fault(&error))?;
    let stop_timeout = properties
        .get(service_interface, "TimeoutStopUSec")
        .await
        .map_err(|error| fdo_fault(&error))?;
    unit_contract(
        &UnitProperties {
            main_pid: u32::try_from(main_pid).map_err(|_| Mismatch)?,
            kill_mode: String::try_from(kill_mode).map_err(|_| Mismatch)?,
            send_kill: bool::try_from(send_kill).map_err(|_| Mismatch)?,
            control_group: String::try_from(group).map_err(|_| Mismatch)?,
            exit_type: String::try_from(exit_type).map_err(|_| Mismatch)?,
            remain: bool::try_from(remain).map_err(|_| Mismatch)?,
            delegated: bool::try_from(delegated).map_err(|_| Mismatch)?,
            stop_timeout: Duration::from_micros(u64::try_from(stop_timeout).map_err(|_| Mismatch)?),
        },
        std::process::id(),
        cgroup,
    )
}

/// The unit properties that startup confirms through the service manager.
#[derive(Clone)]
struct UnitProperties {
    main_pid: u32,
    kill_mode: String,
    send_kill: bool,
    control_group: String,
    exit_type: String,
    remain: bool,
    delegated: bool,
    stop_timeout: Duration,
}

/// Whether the unit that runs the coordinator, as process `pid` in `cgroup`,
/// keeps its crash cleanup and stop contract (ADR 0137, ADR 0141).
fn unit_contract(unit: &UnitProperties, pid: u32, cgroup: &Path) -> Result<(), UnitFault> {
    if unit.main_pid != pid
        || unit.kill_mode != "control-group"
        || !unit.send_kill
        || unit.exit_type != "main"
        || unit.remain
        || unit.delegated
        || unit.stop_timeout > Duration::from_secs(5)
        || Path::new("/sys/fs/cgroup").join(unit.control_group.trim_start_matches('/')) != cgroup
    {
        return Err(UnitFault::Mismatch);
    }
    Ok(())
}

/// One look at a held cgroup's population: `true` when it has no member.
/// A cgroup directory that was removed reports its control files absent, and
/// a cgroup is removable only once it is empty.
fn population(directory: &File) -> Look<bool> {
    use std::os::unix::fs::FileExt;
    let fd = match rustix::fs::openat(
        directory,
        "cgroup.events",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NODEV) => return Ok(true),
        Err(error) => return Err(Unobserved(io::Error::from(error).kind())),
    };
    let file = File::from(fd);
    let mut bytes = [0; 4096];
    let length = match file.read_at(&mut bytes, 0) {
        Ok(length) if length < bytes.len() => length,
        Ok(_) => return Err(Unobserved(io::ErrorKind::InvalidData)),
        Err(error) if error.raw_os_error() == Some(nix::libc::ENODEV) => return Ok(true),
        Err(error) => return Err(Unobserved(error.kind())),
    };
    parse_population(&bytes[..length]).map_err(|_| Unobserved(io::ErrorKind::InvalidData))
}

/// How one look at a workload's population ends its grant.
fn workload_end(population: Look<bool>) -> Option<StopReason> {
    (population == Ok(true)).then_some(StopReason::WorkloadEnded)
}

/// How one look at a pending launch's native owner revokes its grant.
fn launch_revocation(presence: Look<bool>, release_expired: bool) -> Option<StopReason> {
    (presence == Ok(false) || release_expired).then_some(StopReason::WorkloadEnded)
}

/// Whether an execution's client has left, which stops its job.
fn client_left(presence: Look<bool>, hung_up: Look<bool>) -> bool {
    presence == Ok(false) || hung_up == Ok(true)
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

/// No grant survives a coordinator restart, so neither does its routing. The
/// held daemon lock proves that no live instance still owns these markers.
fn clear_markers(runtime: &Path) -> Result<(), Failure> {
    for entry in std::fs::read_dir(runtime).map_err(|_| Failure::NativeUnavailable)? {
        let entry = entry.map_err(|_| Failure::NativeUnavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(Failure::AuthorityDenied);
        };
        if name.starts_with("user-") || name.starts_with("workload-") {
            remove_marker_at(runtime, &parse_marker_name(name)?)?;
        }
    }
    Ok(())
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
            while !population(&child).map_err(|_| Failure::NativeUnavailable)? {
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
            // A vfork-based spawn resumes the parent before the child's new
            // image is installed, so /proc/PID/exe can still name this test.
            let controller_image = File::open("/usr/bin/sleep").unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let image = loop {
                let image = File::open(format!("/proc/{pid}/exe")).unwrap();
                if native::same_file(&image, &controller_image).unwrap() {
                    break image;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "controller never executed"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
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
            assert!(launch_revocation(owner.presence(), owner.release_expired()).is_none());
            assert!(marker.exists());
            controller.0.kill().unwrap();
            controller.0.wait().unwrap();
            assert!(
                !owner.available(),
                "native controller death must immediately deny admission"
            );
            lease.stop(launch_revocation(owner.presence(), owner.release_expired()).unwrap());
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
        assert!(!request_descriptors_valid(
            &ControlRequest::Status { requirement: None },
            2
        ));
        let run = ControlRequest::Run {
            authority: Authority::Administrator,
            duration_seconds: 60,
            executable: "/program".into(),
            execution: super::super::Execution {
                program: "program".into(),
                arguments: vec![],
                working_directory: "/".into(),
                environment: vec![],
                terminal: false,
            },
        };
        for count in 0..=6 {
            assert_eq!(
                request_descriptors_valid(&run, count),
                count == 5,
                "a run carries its streams, its signal channel and its program"
            );
        }
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
    fn missing_ambiguous_or_unreadable_population_is_not_an_answer() {
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

    fn user_scope(uid: u32) -> NativeScope {
        NativeScope {
            account: Account::Unix { uid },
            workload: None,
        }
    }

    /// Coordinator state holding only registry and routing records. These
    /// grants own no native boundary, which `select` never consults.
    fn routing_state(grants: &[(GrantId, NativeScope)]) -> State {
        let mut registry = GrantRegistry::new(MAX_GRANTS).unwrap();
        let limits = dev_tools_privilege_session::GrantLimits::from_administrator_policy(
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        let mut selected = BTreeMap::new();
        for (id, scope) in grants {
            registry
                .issue(
                    *id,
                    scope.clone(),
                    Authority::Administrator,
                    limits,
                    None,
                    Duration::ZERO,
                )
                .unwrap();
            selected.insert(scope.clone(), *id);
        }
        State {
            registry,
            metadata: BTreeMap::new(),
            selected,
            jobs: BTreeMap::new(),
            pending_relays: BTreeMap::new(),
            commands: BTreeMap::new(),
            phase: Phase::Serving,
            unseen: Unseen::default(),
        }
    }

    type GrantEnd = (&'static str, fn(&mut State));

    /// Publish the state's selections as `write_marker` names and contents.
    fn publish(runtime: &Path, state: &State) {
        for (scope, id) in &state.selected {
            std::fs::write(
                runtime.join(marker_name(scope).unwrap()),
                format!("{id:032x}\n"),
            )
            .unwrap();
        }
    }

    fn entries(runtime: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(runtime)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    // A selection that still names an ended grant makes the sudo bridge deny
    // every invocation for the scope until someone knows to run `leave`.
    #[test]
    fn a_grant_ended_by_any_path_no_longer_routes_its_scope() {
        let scope = user_scope(1000);
        let later = Duration::from_secs(1);
        let ends: [GrantEnd; 7] = [
            ("hard expiry", |state| {
                state.registry.poll(Duration::from_secs(61));
            }),
            ("revocation", |state| {
                state
                    .registry
                    .stop(1, StopReason::Revoked, Duration::from_secs(1))
                    .unwrap();
            }),
            ("logout", |state| {
                state
                    .registry
                    .stop(1, StopReason::Logout, Duration::from_secs(1))
                    .unwrap();
            }),
            ("authority change", |state| {
                state
                    .registry
                    .stop_all(StopReason::AuthorityChanged, Duration::from_secs(1));
            }),
            ("coordinator shutdown", |state| {
                state
                    .registry
                    .stop_all(StopReason::BrokerShutdown, Duration::from_secs(1));
            }),
            ("retirement after cleanup", |state| {
                state
                    .registry
                    .stop(1, StopReason::Revoked, Duration::from_secs(1))
                    .unwrap();
                state.registry.report_cleanup(1, Cleanup::Complete).unwrap();
                state.registry.retire(1).unwrap();
            }),
            ("coordinator restart", |state| {
                state.registry = GrantRegistry::new(MAX_GRANTS).unwrap();
            }),
        ];
        for (path, end) in ends {
            let runtime = tempfile::tempdir().unwrap();
            let mut state = routing_state(&[(1, scope.clone())]);
            publish(runtime.path(), &state);
            state.registry.poll(later);
            withdraw_ended_routing(runtime.path(), &mut state);
            assert_eq!(select(&state, &scope, None), Ok(1), "{path}");
            assert_eq!(entries(runtime.path()), ["user-1000"], "{path}");
            end(&mut state);
            assert_eq!(
                select(&state, &scope, None),
                Err(Failure::NoGrant),
                "{path}"
            );
            withdraw_ended_routing(runtime.path(), &mut state);
            assert!(entries(runtime.path()).is_empty(), "{path}");
            assert!(state.selected.is_empty(), "{path}");
        }
    }

    #[test]
    fn ending_one_grant_withdraws_only_its_own_routing() {
        let runtime = tempfile::tempdir().unwrap();
        let ended = user_scope(1000);
        let active = user_scope(1001);
        let mut state = routing_state(&[(1, ended.clone()), (2, active.clone())]);
        publish(runtime.path(), &state);
        state
            .registry
            .stop(1, StopReason::Revoked, Duration::from_secs(1))
            .unwrap();
        withdraw_ended_routing(runtime.path(), &mut state);
        assert_eq!(entries(runtime.path()), ["user-1001"]);
        assert_eq!(select(&state, &active, None), Ok(2));
        assert_eq!(select(&state, &ended, None), Err(Failure::NoGrant));
    }

    #[test]
    fn a_starting_coordinator_withdraws_every_previous_routing_marker() {
        let runtime = tempfile::tempdir().unwrap();
        let state = routing_state(&[
            (1, user_scope(1000)),
            (
                2,
                NativeScope {
                    account: Account::Unix { uid: 1000 },
                    workload: Some(7),
                },
            ),
        ]);
        publish(runtime.path(), &state);
        for kept in ["control.sock", "daemon.lock", "sudo.sock"] {
            std::fs::write(runtime.path().join(kept), b"").unwrap();
        }
        assert_eq!(entries(runtime.path()).len(), 5);
        clear_markers(runtime.path()).unwrap();
        assert_eq!(
            entries(runtime.path()),
            ["control.sock", "daemon.lock", "sudo.sock"]
        );
    }

    #[test]
    fn a_workload_whose_grant_ended_returns_to_its_accounts_selected_grant() {
        let user = user_scope(1000);
        let workload = NativeScope {
            account: Account::Unix { uid: 1000 },
            workload: Some(7),
        };
        let mut state = routing_state(&[(1, user.clone()), (2, workload.clone())]);
        assert_eq!(select(&state, &workload, None), Ok(2));
        state
            .registry
            .stop(2, StopReason::WorkloadEnded, Duration::from_secs(1))
            .unwrap();
        assert_eq!(select(&state, &workload, None), Ok(1));
        assert_eq!(select(&state, &user, None), Ok(1));
    }

    #[derive(Clone, Copy)]
    enum Answer {
        Confirmed,
        Fault(UnitFault),
        Silent,
    }

    type Verification = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), UnitFault>>>>;

    fn scripted(
        answers: &[Answer],
    ) -> (
        std::rc::Rc<std::cell::Cell<usize>>,
        impl FnMut() -> Verification,
    ) {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let answers = answers.to_vec();
        let counter = std::rc::Rc::clone(&calls);
        let verify = move || -> Verification {
            let call = counter.get();
            counter.set(call + 1);
            let answer = answers.get(call).copied();
            Box::pin(async move {
                match answer {
                    Some(Answer::Confirmed) => Ok(()),
                    Some(Answer::Silent) => std::future::pending().await,
                    Some(Answer::Fault(fault)) => Err(fault),
                    None => panic!("verified after the scripted answers ran out"),
                }
            })
        };
        (calls, verify)
    }

    const QUICK: Backoff = Backoff {
        attempt: Duration::from_millis(20),
        first_delay: Duration::from_millis(1),
        longest_delay: Duration::from_millis(4),
        total: Duration::from_secs(10),
    };

    #[tokio::test]
    async fn unit_verification_retries_while_the_service_manager_is_unreachable() {
        let (calls, verify) = scripted(&[
            Answer::Fault(UnitFault::Unreachable),
            Answer::Fault(UnitFault::Unreachable),
            Answer::Confirmed,
        ]);
        assert_eq!(verify_unit(verify, QUICK).await, Ok(()));
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn unit_verification_retries_a_service_manager_that_does_not_answer() {
        let (calls, verify) = scripted(&[Answer::Silent, Answer::Confirmed]);
        assert_eq!(verify_unit(verify, QUICK).await, Ok(()));
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn a_unit_that_breaks_the_cleanup_contract_fails_without_retrying() {
        let (calls, verify) = scripted(&[Answer::Fault(UnitFault::Mismatch)]);
        assert_eq!(
            verify_unit(verify, QUICK).await,
            Err(Failure::NativeUnavailable)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn only_an_undelivered_call_leaves_the_service_manager_unanswered() {
        use zbus::fdo::Error as Reply;
        let undelivered = [
            zbus::Error::InputOutput(Arc::new(io::ErrorKind::ConnectionRefused.into())),
            zbus::Error::FDO(Box::new(Reply::NameHasNoOwner("systemd".into()))),
            zbus::Error::FDO(Box::new(Reply::ServiceUnknown("systemd".into()))),
            zbus::Error::FDO(Box::new(Reply::NoReply("timeout".into()))),
        ];
        for error in &undelivered {
            assert_eq!(bus_fault(error), UnitFault::Unreachable, "{error}");
        }
        assert_eq!(
            fdo_fault(&Reply::Disconnected("bus".into())),
            UnitFault::Unreachable
        );
        let answered = [
            zbus::Error::FDO(Box::new(Reply::AccessDenied("policy".into()))),
            zbus::Error::FDO(Box::new(Reply::UnknownProperty("KillMode".into()))),
            zbus::Error::InvalidReply,
        ];
        for error in &answered {
            assert_eq!(bus_fault(error), UnitFault::Mismatch, "{error}");
        }
        assert_eq!(
            reply_fault("org.freedesktop.systemd1.NoUnitForPID"),
            UnitFault::Mismatch
        );
        assert_eq!(
            reply_fault("org.freedesktop.DBus.Error.NameHasNoOwner"),
            UnitFault::Unreachable
        );
    }

    #[tokio::test]
    async fn unit_verification_gives_up_when_its_budget_ends() {
        let (calls, verify) = scripted(&[Answer::Fault(UnitFault::Unreachable); 10_000]);
        let budget = Backoff {
            total: Duration::from_millis(50),
            ..QUICK
        };
        let started = std::time::Instant::now();
        assert_eq!(
            verify_unit(verify, budget).await,
            Err(Failure::NativeUnavailable)
        );
        assert!(
            calls.get() >= 2,
            "retried before giving up: {}",
            calls.get()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    fn active(state: &State, id: GrantId) -> bool {
        state
            .registry
            .get(id)
            .is_some_and(|grant| grant.lifetime.state() == LeaseState::Active)
    }

    const UNREADABLE: Unobserved = Unobserved(io::ErrorKind::Interrupted);

    #[test]
    fn a_changed_trust_input_closes_admission_and_keeps_running_grants() {
        for input in [Input::SudoProgram, Input::Policy] {
            let scope = user_scope(1000);
            let mut state = routing_state(&[(1, scope.clone())]);
            watch_trust(&mut state, Ok(Some(input)));
            assert!(
                active(&state, 1),
                "{input}: the grant and its job keep running"
            );
            assert_eq!(
                select(&state, &scope, None),
                Ok(1),
                "{input}: routing stays"
            );
            assert!(
                admission(state.phase, Ok(None)).is_err(),
                "{input}: nothing new is admitted under the old trust, even after a clean look"
            );
            assert_eq!(
                state.phase.drained(1, 0, true, Duration::ZERO),
                None,
                "{input}: waits for its running job"
            );
            assert_eq!(
                state.phase.drained(0, 0, false, Duration::ZERO),
                None,
                "{input}: and for its connections"
            );
            assert_eq!(
                state.phase.drained(0, 0, true, Duration::ZERO),
                Some(Exit::Changed(input)),
                "{input}: exits for a restart once no job runs"
            );
            assert_eq!(
                state.phase.drained(0, 1, true, Duration::ZERO),
                (input == Input::Policy).then_some(Exit::Changed(input)),
                "{input}: a grant approved under the old policy ends at the exit, and one that keeps its use across a sudo-program change is waited for"
            );
        }
        let mut state = routing_state(&[(1, user_scope(1000))]);
        watch_trust(&mut state, Ok(Some(Input::SudoProgram)));
        watch_trust(&mut state, Ok(Some(Input::Policy)));
        assert_eq!(
            state.phase.drained(0, 1, true, Duration::ZERO),
            Some(Exit::Changed(Input::Policy)),
            "a later policy change ends the use that grants kept"
        );
    }

    #[test]
    fn ending_and_observing_grants_never_wait_for_trust() {
        let grant = "0123456789abcdef0123456789abcdef".to_owned();
        for request in [
            ControlRequest::Status { requirement: None },
            ControlRequest::Inspect {
                grant: grant.clone(),
            },
            ControlRequest::Revoke {
                grant: grant.clone(),
            },
            ControlRequest::Leave,
        ] {
            assert!(!admits_new_work(&request), "{}", request.operation());
        }
        assert!(!admits_new_work(&ControlRequest::Status {
            requirement: Some(GrantRequirement {
                remaining_seconds: 60,
                scope: None,
            }),
        }));
        for request in [
            ControlRequest::Run {
                authority: Authority::Administrator,
                duration_seconds: 60,
                executable: "/program".into(),
                execution: super::super::Execution {
                    program: "program".into(),
                    arguments: vec![],
                    working_directory: "/".into(),
                    environment: vec![],
                    terminal: false,
                },
            },
            ControlRequest::CommitLaunch {
                grant: grant.clone(),
            },
            ControlRequest::ActivateLaunch {
                grant,
                bootstrap: false,
            },
        ] {
            assert!(admits_new_work(&request), "{}", request.operation());
        }
    }

    #[test]
    fn a_trust_input_that_cannot_be_read_is_not_a_change() {
        let bound = FileStamp {
            device: 1,
            inode: 2,
            length: 3,
            mtime: 4,
            mtime_ns: 5,
            ctime: 6,
            ctime_ns: 7,
        };
        let replaced = FileStamp { inode: 9, ..bound };
        assert_eq!(unchanged(bound, Ok(bound), Ok(Some(bound))), Ok(true));
        assert_eq!(
            unchanged(bound, Ok(bound), Err(UNREADABLE)),
            Err(UNREADABLE),
            "a path that cannot be opened now"
        );
        assert_eq!(
            unchanged(bound, Err(UNREADABLE), Ok(Some(bound))),
            Err(UNREADABLE),
            "a held descriptor that cannot be stamped now"
        );
        assert_eq!(unchanged(bound, Ok(bound), Ok(Some(replaced))), Ok(false));
        assert_eq!(unchanged(bound, Ok(replaced), Ok(Some(bound))), Ok(false));
        assert_eq!(unchanged(bound, Ok(bound), Ok(None)), Ok(false));
        assert_eq!(
            unchanged(bound, Ok(replaced), Err(UNREADABLE)),
            Ok(false),
            "an observed change wins over a look that failed"
        );
        assert_eq!(
            changed_input([
                (Input::Policy, Err(UNREADABLE)),
                (Input::SudoProgram, Ok(true))
            ]),
            Err(UNREADABLE)
        );
        let scope = user_scope(1000);
        let mut state = routing_state(&[(1, scope.clone())]);
        watch_trust(&mut state, Err(UNREADABLE));
        assert!(active(&state, 1), "the grant and its job keep running");
        assert!(
            admission(state.phase, Err(UNREADABLE)).is_err(),
            "only this admission is refused"
        );
        assert_eq!(
            admission(state.phase, Ok(None)),
            Ok(()),
            "and the next is not"
        );
        assert_eq!(state.phase.drained(0, 0, true, Duration::ZERO), None);
    }

    #[test]
    fn a_workload_population_that_cannot_be_read_does_not_end_its_grant() {
        let cgroup = tempfile::tempdir().unwrap();
        let held = File::open(cgroup.path()).unwrap();
        let events = cgroup.path().join("cgroup.events");
        std::fs::write(&events, "populated 1\nfrozen 0\n").unwrap();
        assert_eq!(population(&held), Ok(false));
        assert_eq!(workload_end(population(&held)), None);
        std::fs::write(&events, "populated 0\nfrozen 0\n").unwrap();
        assert_eq!(
            workload_end(population(&held)),
            Some(StopReason::WorkloadEnded)
        );
        std::fs::remove_file(&events).unwrap();
        assert_eq!(
            population(&held),
            Ok(true),
            "a removed cgroup has no member"
        );
        let unreadable: [fn(&Path); 2] = [
            |events| std::fs::create_dir(events).unwrap(),
            |events| std::fs::write(events, "populated 2\n").unwrap(),
        ];
        for unreadable in unreadable {
            let _ = std::fs::remove_dir(&events);
            let _ = std::fs::remove_file(&events);
            unreadable(&events);
            assert!(population(&held).is_err());
            assert_eq!(workload_end(population(&held)), None);
        }
    }

    #[test]
    fn only_a_symlink_or_wrong_type_is_an_observed_unprotected_path() {
        for observed in [nix::libc::ELOOP, nix::libc::ENOTDIR] {
            assert!(matches!(
                opened(Err(io::Error::from_raw_os_error(observed))),
                Ok(None)
            ));
        }
        for unobserved in [
            nix::libc::ENOENT,
            nix::libc::EACCES,
            nix::libc::EMFILE,
            nix::libc::ENFILE,
            nix::libc::ENOMEM,
            nix::libc::EIO,
            nix::libc::EINTR,
        ] {
            assert!(
                opened(Err(io::Error::from_raw_os_error(unobserved))).is_err(),
                "errno {unobserved}"
            );
        }
    }

    #[test]
    fn a_launch_owner_that_cannot_be_observed_is_not_revoked() {
        assert_eq!(launch_revocation(Ok(true), false), None);
        assert_eq!(launch_revocation(Err(UNREADABLE), false), None);
        for (presence, expired) in [
            (Ok(false), false),
            (Ok(true), true),
            (Err(UNREADABLE), true),
        ] {
            assert_eq!(
                launch_revocation(presence, expired),
                Some(StopReason::WorkloadEnded)
            );
        }
    }

    #[test]
    fn a_client_that_cannot_be_observed_has_not_left() {
        assert!(!client_left(Ok(true), Ok(false)));
        assert!(!client_left(Err(UNREADABLE), Ok(false)));
        assert!(!client_left(Ok(true), Err(UNREADABLE)));
        assert!(client_left(Ok(false), Err(UNREADABLE)));
        assert!(client_left(Err(UNREADABLE), Ok(true)));
    }

    // check_logins stops every user grant of the account, and with it all of
    // their running jobs, whenever this returns true.
    #[test]
    fn only_an_observed_logout_ends_user_grants() {
        assert!(!login_ended(Ok(true)));
        assert!(login_ended(Ok(false)));
        for failure in [Failure::NativeUnavailable, Failure::ProtocolViolation] {
            assert!(
                !login_ended(Err(failure)),
                "an unanswered login query ended user grants: {failure:?}"
            );
        }
    }

    /// A forked child whose exit the test controls. It runs no program.
    struct Leader {
        pid: nix::unistd::Pid,
        reaped: bool,
    }

    impl Leader {
        fn start() -> Self {
            // SAFETY: the child calls only async-signal-safe pause and never
            // returns into the test harness.
            match unsafe { nix::unistd::fork() }.unwrap() {
                nix::unistd::ForkResult::Child => loop {
                    unsafe { nix::libc::pause() };
                },
                nix::unistd::ForkResult::Parent { child } => Self {
                    pid: child,
                    reaped: false,
                },
            }
        }

        fn pidfd(&self) -> OwnedFd {
            rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(self.pid.as_raw()).unwrap(),
                rustix::process::PidfdFlags::empty(),
            )
            .unwrap()
        }

        fn exit(&mut self) {
            nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGKILL).unwrap();
            nix::sys::wait::waitpid(self.pid, None).unwrap();
            self.reaped = true;
        }
    }

    impl Drop for Leader {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(self.pid, None);
            }
        }
    }

    fn command_scope(uid: u32, boundary: &File) -> NativeScope {
        NativeScope {
            account: Account::Unix { uid },
            workload: Some(command::cgroup_key(boundary).unwrap()),
        }
    }

    #[test]
    fn a_command_grant_ends_when_its_program_exits() {
        let boundary = tempfile::tempdir().unwrap();
        let scope = command_scope(1000, &File::open(boundary.path()).unwrap());
        let mut state = routing_state(&[(1, scope.clone())]);
        let mut leader = Leader::start();
        state.commands.insert(1, leader.pidfd());
        assert!(command::end_exited(&mut state, Duration::from_secs(1)).is_ok());
        assert!(active(&state, 1), "the grant lasts while its program runs");
        assert_eq!(select(&state, &scope, None), Ok(1));
        leader.exit();
        assert!(command::end_exited(&mut state, Duration::from_secs(2)).is_ok());
        assert_eq!(
            state.registry.get(1).unwrap().lifetime.state(),
            LeaseState::Stopping {
                reason: StopReason::WorkloadEnded,
                cleanup_failed: false
            }
        );
        assert_eq!(select(&state, &scope, None), Err(Failure::NoGrant));
        assert!(command::end_exited(&mut state, Duration::from_secs(3)).is_ok());
    }

    #[test]
    fn only_the_programs_own_boundary_routes_through_its_grant() {
        // Directory identity stands in for the kernel cgroup identity that the
        // coordinator reads from a sudo process's peer evidence.
        let program_boundary = tempfile::tempdir().unwrap();
        let sibling_cgroup = tempfile::tempdir().unwrap();
        let boundary = File::open(program_boundary.path()).unwrap();
        let run = command_scope(1000, &boundary);
        let account = user_scope(1000);
        let mut state = routing_state(&[(1, run.clone())]);
        let jobs = || [(7, &boundary)];

        let member = File::open(program_boundary.path()).unwrap();
        assert_eq!(job_in_cgroup(jobs(), &member), Ok(Some(7)));
        assert_eq!(
            select(&state, &run, None),
            Ok(1),
            "the tree routes through its grant"
        );

        let sibling = File::open(sibling_cgroup.path()).unwrap();
        assert_eq!(
            job_in_cgroup(jobs(), &sibling),
            Ok(None),
            "a sibling keeps its own scope"
        );
        assert_eq!(
            select(&state, &account, None),
            Err(Failure::NoGrant),
            "a sibling process of the same account is not routed"
        );
        assert!(
            state
                .registry
                .admit(
                    1,
                    &account,
                    &Authority::Administrator,
                    Duration::from_secs(1)
                )
                .is_err(),
            "naming the grant does not widen it to a sibling"
        );
        assert!(state
            .registry
            .admit(1, &run, &Authority::Administrator, Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn a_remaining_time_requirement_checks_the_grant_that_covers_the_caller() {
        let boundary = tempfile::tempdir().unwrap();
        let run = command_scope(1000, &File::open(boundary.path()).unwrap());
        let account = user_scope(1000);
        let state = routing_state(&[(1, account.clone()), (2, run.clone())]);
        let scopes = BTreeMap::from([(1, GrantScope::User), (2, GrantScope::Command)]);
        let scope_of = |id| scopes.get(&id).copied();
        assert_eq!(
            covering(&state, &run, None, scope_of),
            Ok(2),
            "inside the tree, sudo routes through the command grant"
        );
        assert_eq!(covering(&state, &account, None, scope_of), Ok(1));
        assert_eq!(
            covering(&state, &run, Some(GrantScope::User), scope_of),
            Ok(1),
            "a scope selects the caller's routable grant of that scope"
        );
        assert_eq!(
            covering(&state, &account, Some(GrantScope::Command), scope_of),
            Err(Failure::NoGrant),
            "outside the tree no command grant covers the caller"
        );
        assert_eq!(
            covering(&state, &user_scope(1001), None, scope_of),
            Err(Failure::NoGrant)
        );
        let mut ended = state;
        ended
            .registry
            .stop(2, StopReason::WorkloadEnded, Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            covering(&ended, &run, Some(GrantScope::Command), scope_of),
            Err(Failure::NoGrant),
            "an ended grant covers nothing"
        );
    }

    fn at(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    #[test]
    fn an_orderly_stop_closes_admission_and_lets_running_jobs_finish_within_its_drain() {
        let phase = Phase::Serving.stop_requested(at(100));
        assert!(
            admission(phase, Ok(None)).is_err(),
            "nothing new is admitted"
        );
        assert_eq!(
            phase.drained(1, 0, true, at(159)),
            None,
            "a running job keeps the drain open"
        );
        assert_eq!(
            phase.drained(0, 1, false, at(101)),
            Some(Exit::Stopped),
            "the drain ends once no job runs, and connections finish afterwards"
        );
        assert_eq!(
            phase.drained(1, 1, true, at(160)),
            Some(Exit::Stopped),
            "the drain is bounded"
        );
        assert_eq!(
            phase.stop_requested(at(130)),
            phase,
            "a repeated request keeps the first bound"
        );
    }

    #[test]
    fn a_stop_during_a_trust_change_drain_becomes_the_bounded_stop_drain() {
        let phase = Phase::Draining(Drain::Changed(Input::SudoProgram)).stop_requested(at(100));
        assert_eq!(phase.drained(1, 0, true, at(159)), None);
        assert_eq!(phase.drained(1, 1, false, at(160)), Some(Exit::Stopped));
        assert_eq!(
            phase.drained(0, 1, false, at(101)),
            Some(Exit::Stopped),
            "a stopped coordinator exits with success, not for a restart"
        );
    }

    #[tokio::test]
    async fn a_stopping_coordinator_lets_finishing_connections_deliver_their_results() {
        use std::os::unix::net::UnixStream;
        let (coordinator, client) = UnixStream::pair().unwrap();
        let mut connections = tokio::task::JoinSet::new();
        connections.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            (&coordinator).write_all(b"exec result").unwrap();
        });
        connections.spawn(std::future::pending());
        let started = std::time::Instant::now();
        finish_connections(&mut connections, Duration::from_millis(500)).await;
        assert!(connections.is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a connection that never finishes is cancelled at the bound"
        );
        let mut received = Vec::new();
        (&client).read_to_end(&mut received).unwrap();
        assert_eq!(received, b"exec result");
    }

    fn drainable_unit() -> UnitProperties {
        UnitProperties {
            main_pid: 7,
            kill_mode: "mixed".into(),
            send_kill: true,
            control_group: "/system.slice/dev-auth-grants.service".into(),
            exit_type: "main".into(),
            remain: false,
            delegated: false,
            stop_timeout: at(90),
        }
    }

    const UNIT_CGROUP: &str = "/sys/fs/cgroup/system.slice/dev-auth-grants.service";

    #[test]
    fn startup_requires_a_unit_that_lets_the_coordinator_drain_before_anything_is_killed() {
        let cgroup = Path::new(UNIT_CGROUP);
        assert_eq!(unit_contract(&drainable_unit(), 7, cgroup), Ok(()));
        for (unit, why) in [
            (
                UnitProperties {
                    kill_mode: "control-group".into(),
                    ..drainable_unit()
                },
                "the service manager would send SIGTERM to every job at a stop",
            ),
            (
                UnitProperties {
                    stop_timeout: at(5),
                    ..drainable_unit()
                },
                "the stop timeout would cut the drain short",
            ),
            (
                UnitProperties {
                    send_kill: false,
                    ..drainable_unit()
                },
                "jobs would outlive the coordinator",
            ),
            (
                UnitProperties {
                    delegated: true,
                    ..drainable_unit()
                },
                "a delegated unit gives up the boundaries",
            ),
        ] {
            assert_eq!(
                unit_contract(&unit, 7, cgroup),
                Err(UnitFault::Mismatch),
                "{why}"
            );
        }
    }

    #[test]
    fn the_shipped_unit_satisfies_the_startup_contract() {
        let setting = |key: &str| {
            super::super::assets::SERVICE
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_else(|| panic!("{key} is unset"))
                .to_owned()
        };
        let seconds = setting("TimeoutStopSec");
        let unit = UnitProperties {
            main_pid: 7,
            kill_mode: setting("KillMode"),
            send_kill: setting("SendSIGKILL") == "yes",
            control_group: "/system.slice/dev-auth-grants.service".into(),
            exit_type: setting("ExitType"),
            remain: setting("RemainAfterExit") == "yes",
            delegated: setting("Delegate") == "yes",
            stop_timeout: at(seconds.strip_suffix('s').unwrap().parse().unwrap()),
        };
        assert_eq!(unit_contract(&unit, 7, Path::new(UNIT_CGROUP)), Ok(()));
    }

    #[test]
    fn a_replaced_sudo_program_is_selected_only_through_the_startup_validation() {
        let directory = tempfile::tempdir().unwrap();
        let bound = directory.path().join("bound");
        let replaced = directory.path().join("replaced");
        std::fs::write(&bound, b"bound").unwrap();
        std::fs::write(&replaced, b"replaced").unwrap();
        let held = File::open(&bound).unwrap();
        let unchanged = current_sudo(Ok(true), &held, || -> Result<File, Failure> {
            panic!("an unchanged program is not validated again")
        })
        .unwrap();
        assert!(native::same_file(&unchanged, &held).unwrap());
        let selected = current_sudo(Ok(false), &held, || Ok(File::open(&replaced).unwrap()))
            .expect("a replaced program that passes the startup validation is selected");
        assert!(native::same_file(&selected, &File::open(&replaced).unwrap()).unwrap());
        assert_eq!(
            current_sudo(Ok(false), &held, || Err(Failure::AuthorityDenied)).err(),
            Some(Failure::AuthorityDenied),
            "a replacement that fails the validation refuses the connection"
        );
        assert!(
            current_sudo(Err(UNREADABLE), &held, || -> Result<File, Failure> {
                panic!("a look that could not be taken selects nothing")
            })
            .is_err()
        );
    }

    #[test]
    fn admitted_grants_keep_managed_sudo_across_a_sudo_program_change_only() {
        let sudo_drain = Phase::Draining(Drain::Changed(Input::SudoProgram));
        let policy_drain = Phase::Draining(Drain::Changed(Input::Policy));
        let stop = Phase::Draining(Drain::Stop { until: at(60) });
        for (phase, policy, expected, why) in [
            (Phase::Serving, Ok(true), GrantUse::Open, "serving"),
            (
                sudo_drain,
                Ok(true),
                GrantUse::Open,
                "a replaced sudo program",
            ),
            (
                sudo_drain,
                Ok(false),
                GrantUse::Draining,
                "a policy change as well",
            ),
            (
                Phase::Serving,
                Ok(false),
                GrantUse::Draining,
                "a policy change not yet reaped",
            ),
            (
                policy_drain,
                Ok(true),
                GrantUse::Draining,
                "grants approved under the old policy",
            ),
            (stop, Ok(true), GrantUse::Draining, "an orderly stop"),
            (Phase::Stopping, Ok(true), GrantUse::Draining, "shutdown"),
            (
                Phase::Serving,
                Err(UNREADABLE),
                GrantUse::Unobserved,
                "an unreadable policy",
            ),
            (
                sudo_drain,
                Err(UNREADABLE),
                GrantUse::Unobserved,
                "an unreadable policy in a drain",
            ),
        ] {
            assert_eq!(grant_use(phase, policy), expected, "{why}");
        }
    }

    #[test]
    fn only_work_under_an_existing_grant_continues_through_a_sudo_program_drain() {
        let grant = "0123456789abcdef0123456789abcdef".to_owned();
        let execution = || super::super::Execution {
            program: "/usr/bin/true".into(),
            arguments: vec![],
            working_directory: "/".into(),
            environment: vec![],
            terminal: false,
        };
        for request in [
            ControlRequest::Exec {
                grant: None,
                execution: execution(),
            },
            ControlRequest::SudoRelay {
                grant: grant.clone(),
                execution: execution(),
            },
        ] {
            assert!(uses_existing_grant(&request), "{}", request.operation());
        }
        for request in [
            ControlRequest::Request {
                request: GrantRequest::command(Authority::Administrator, 60),
            },
            ControlRequest::Delegate {
                grant,
                request: GrantRequest::command(Authority::Administrator, 60),
            },
        ] {
            assert!(
                !uses_existing_grant(&request),
                "{}: a new grant waits for the coordinator that binds the new state",
                request.operation()
            );
        }
    }

    #[test]
    fn a_routed_sudo_during_a_drain_is_told_to_rerun_and_an_unrouted_one_has_native_sudo() {
        assert_eq!(
            preflight_answer(Ok(7), GrantUse::Draining),
            Ok(Preflight::Draining)
        );
        assert_eq!(
            preflight_answer(Err(Failure::NoGrant), GrantUse::Draining),
            Ok(Preflight::Native)
        );
        assert_eq!(
            preflight_answer(Ok(7), GrantUse::Open),
            Ok(Preflight::Admit(7))
        );
        assert_eq!(
            preflight_answer(Ok(7), GrantUse::Unobserved),
            Err(Failure::NativeUnavailable)
        );
    }
}
