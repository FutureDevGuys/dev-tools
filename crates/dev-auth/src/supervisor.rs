use crate::control_protocol::{ControlRequest, ControlResponse};
use crate::linux_admission::{session_authority_from_resolved, SessionRegistration};
use crate::policy_v2::{
    ResolvedAuthorityProfile, ResolvedPolicy, ResolvedWorkload, SandboxMode, SystemMode,
};
use anyhow::{bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{getsockopt, sockopt};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

const ENVIRONMENT_LIMIT: u64 = 1024 * 1024;
const ENVIRONMENT_MAGIC: &[u8] = b"DEV-AUTH-ENV-V1\0";
const ENVIRONMENT_ENTRY_LIMIT: usize = 4096;
const SESSION_LEASE_SECONDS: i64 = 15 * 60;
const SESSION_RENEW_SECONDS: u64 = 10 * 60;
const SESSION_REASSOCIATION_SECONDS: u64 = 30;
const SESSION_REASSOCIATION_RETRY_MILLIS: u64 = 250;
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(120);
const ENVIRONMENT_HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);

struct TransientServiceRequest<'a> {
    session_id: &'a str,
    owner_uid: u32,
    workload: &'a str,
    cwd: &'a Path,
    launcher_pid: u32,
    environment_socket: &'a Path,
    executable: &'a Path,
    arguments: &'a [OsString],
}

struct GatedChildRequest<'a> {
    owner_uid: u32,
    owner: &'a nix::unistd::User,
    session_id: &'a str,
    workload: &'a str,
    cgroup: &'a Path,
    launcher: &'a Path,
    cwd: &'a Path,
    arguments: &'a [OsString],
    environment: BTreeMap<OsString, OsString>,
    sandbox: Option<SandboxLaunch>,
}

struct GatedChild {
    child: Child,
    release: OwnedFd,
}

struct AgentProxyProcess {
    child: Child,
    socket: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxLaunch {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub argument_separator: bool,
}

fn encode_workload_environment(environment: &BTreeMap<OsString, OsString>) -> Result<Vec<u8>> {
    if environment.len() > ENVIRONMENT_ENTRY_LIMIT {
        bail!("workload environment contains too many entries");
    }
    let mut output = Vec::with_capacity(ENVIRONMENT_MAGIC.len() + 4 + environment.len() * 16);
    output.extend_from_slice(ENVIRONMENT_MAGIC);
    output.extend_from_slice(
        &u32::try_from(environment.len())
            .context("workload environment entry count exceeds the wire format")?
            .to_be_bytes(),
    );
    for (name, value) in environment {
        if !environment_name_is_safe(name)
            || name.as_bytes().contains(&b'=')
            || name.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
        {
            bail!("workload environment contains an unsafe entry");
        }
        for bytes in [name.as_bytes(), value.as_bytes()] {
            output.extend_from_slice(
                &u32::try_from(bytes.len())
                    .context("workload environment entry exceeds the wire format")?
                    .to_be_bytes(),
            );
            output.extend_from_slice(bytes);
        }
        if output.len() as u64 > ENVIRONMENT_LIMIT {
            bail!("workload environment exceeds the size limit");
        }
    }
    Ok(output)
}

fn decode_workload_environment(input: &[u8]) -> Result<BTreeMap<OsString, OsString>> {
    if input.len() as u64 > ENVIRONMENT_LIMIT || !input.starts_with(ENVIRONMENT_MAGIC) {
        bail!("workload environment frame is invalid or oversized");
    }
    let mut offset = ENVIRONMENT_MAGIC.len();
    let count = read_environment_length(input, &mut offset)?;
    if count > ENVIRONMENT_ENTRY_LIMIT {
        bail!("workload environment contains too many entries");
    }
    let mut environment = BTreeMap::new();
    for _ in 0..count {
        let name_length = read_environment_length(input, &mut offset)?;
        let name = take_environment_bytes(input, &mut offset, name_length)?;
        let value_length = read_environment_length(input, &mut offset)?;
        let value = take_environment_bytes(input, &mut offset, value_length)?;
        let name = OsStr::from_bytes(name);
        if !environment_name_is_safe(name)
            || name.as_bytes().contains(&b'=')
            || name.as_bytes().contains(&0)
            || value.contains(&0)
        {
            bail!("workload environment frame contains an unsafe entry");
        }
        if environment
            .insert(name.to_os_string(), OsStr::from_bytes(value).to_os_string())
            .is_some()
        {
            bail!("workload environment frame contains a duplicate entry");
        }
    }
    if offset != input.len() {
        bail!("workload environment frame contains trailing data");
    }
    Ok(environment)
}

fn read_environment_length(input: &[u8], offset: &mut usize) -> Result<usize> {
    let bytes = take_environment_bytes(input, offset, 4)?;
    Ok(u32::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("workload environment length is malformed"))?,
    ) as usize)
}

fn take_environment_bytes<'a>(
    input: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .context("workload environment length overflow")?;
    let bytes = input
        .get(*offset..end)
        .context("workload environment frame is truncated")?;
    *offset = end;
    Ok(bytes)
}

fn transient_service_arguments(request: &TransientServiceRequest<'_>) -> Result<Vec<OsString>> {
    validate_identifier(request.session_id, "session identifier")?;
    validate_identifier(request.workload, "workload")?;
    if request.owner_uid == 0
        || request.launcher_pid == 0
        || !request.cwd.is_absolute()
        || !request.environment_socket.is_absolute()
    {
        bail!("transient workload boundary contains invalid public selectors");
    }
    let unit = format!("dev-auth-workload-{}", request.session_id);
    let mut command = vec![
        OsString::from("--quiet"),
        OsString::from("--wait"),
        OsString::from("--collect"),
        OsString::from("--pipe"),
        OsString::from("--service-type=exec"),
        OsString::from(format!("--unit={unit}")),
        OsString::from("--property=KillMode=control-group"),
        OsString::from("--property=SendSIGKILL=yes"),
        OsString::from("--property=TimeoutStopSec=10s"),
        OsString::from("--property=Delegate=no"),
        OsString::from("--property=CollectMode=inactive-or-failed"),
        OsString::from("--"),
        request.executable.as_os_str().to_os_string(),
        OsString::from("supervisor"),
        OsString::from("launch"),
        OsString::from("--uid"),
        OsString::from(request.owner_uid.to_string()),
        OsString::from("--workload"),
        OsString::from(request.workload),
        OsString::from("--cwd"),
        request.cwd.as_os_str().to_os_string(),
        OsString::from("--session"),
        OsString::from(request.session_id),
        OsString::from("--launcher-pid"),
        OsString::from(request.launcher_pid.to_string()),
        OsString::from("--environment-socket"),
        request.environment_socket.as_os_str().to_os_string(),
        OsString::from("--"),
    ];
    command.extend_from_slice(request.arguments);
    Ok(command)
}

fn create_environment_listener(owner_uid: u32) -> Result<(UnixListener, PathBuf, Vec<u8>)> {
    let runtime_root = PathBuf::from(format!("/run/user/{owner_uid}"));
    validate_private_runtime_directory(&runtime_root, owner_uid)?;
    let handoff_root = runtime_root.join("dev-auth-v3");
    match fs::create_dir(&handoff_root) {
        Ok(()) => fs::set_permissions(&handoff_root, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create workload handoff directory"),
    }
    validate_private_runtime_directory(&handoff_root, owner_uid)?;
    let path = handoff_root.join(format!("launch-{}.sock", random_session_id()?));
    let listener = UnixListener::bind(&path).context("bind private workload handoff socket")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .context("protect workload handoff socket")?;
    let metadata = fs::symlink_metadata(&path).context("inspect workload handoff socket")?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        let _ = fs::remove_file(&path);
        bail!("workload handoff socket has unsafe authority");
    }
    listener
        .set_nonblocking(true)
        .context("make workload handoff listener nonblocking")?;
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| environment_name_is_safe(name))
        .collect::<BTreeMap<_, _>>();
    environment.remove(OsStr::new("HOME"));
    environment.remove(OsStr::new("USER"));
    environment.remove(OsStr::new("LOGNAME"));
    let frame = encode_workload_environment(&environment)?;
    Ok((listener, path, frame))
}

fn send_environment_to_supervisor(
    listener: &UnixListener,
    frame: &[u8],
    child: &mut Child,
) -> Result<()> {
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let credentials = getsockopt(&stream, sockopt::PeerCredentials)
                    .context("authenticate workload handoff receiver")?;
                if credentials.uid() != 0 {
                    bail!("workload handoff receiver is not root-owned");
                }
                stream
                    .write_all(
                        &u32::try_from(frame.len())
                            .context("workload environment exceeds the handoff protocol")?
                            .to_be_bytes(),
                    )
                    .context("write workload environment frame length")?;
                stream
                    .write_all(frame)
                    .context("write workload environment frame")?;
                stream.flush().context("flush workload environment frame")?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("accept workload environment handoff"),
        }
        if let Some(status) = child
            .try_wait()
            .context("poll privileged workload dispatcher")?
        {
            bail!("privileged workload dispatch ended before admission: {status}");
        }
        if started.elapsed() >= AUTHORIZATION_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("privileged workload authorization timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn receive_workload_environment(
    owner_uid: u32,
    launcher_pid: u32,
    path: &Path,
) -> Result<BTreeMap<OsString, OsString>> {
    validate_environment_socket_path(owner_uid, path)?;
    let mut stream =
        UnixStream::connect(path).context("connect to workload environment handoff")?;
    let credentials = getsockopt(&stream, sockopt::PeerCredentials)
        .context("authenticate workload environment sender")?;
    if credentials.uid() != owner_uid || credentials.pid() != i32::try_from(launcher_pid)? {
        bail!("workload environment sender does not match the admitted launcher");
    }
    let launcher_pidfd = getsockopt(&stream, sockopt::PeerPidfd)
        .context("hold the workload environment sender identity")?;
    let mut descriptors = [PollFd::new(launcher_pidfd.as_fd(), PollFlags::POLLIN)];
    if poll(&mut descriptors, PollTimeout::ZERO).context("poll workload environment sender")? != 0 {
        bail!("workload environment sender exited before handoff");
    }
    let _ = fs::remove_file(path);
    stream
        .set_read_timeout(Some(ENVIRONMENT_HANDOFF_TIMEOUT))
        .context("bound workload environment handoff")?;
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .context("read workload environment frame length")?;
    let length = u32::from_be_bytes(length) as usize;
    if length as u64 > ENVIRONMENT_LIMIT {
        bail!("workload environment frame exceeds the size limit");
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .context("read workload environment frame")?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .context("finish workload environment frame")?
        != 0
    {
        bail!("workload environment handoff contains trailing data");
    }
    decode_workload_environment(&frame)
}

fn validate_environment_socket_path(owner_uid: u32, path: &Path) -> Result<()> {
    let runtime_root = PathBuf::from(format!("/run/user/{owner_uid}"));
    let handoff_root = runtime_root.join("dev-auth-v3");
    if path.parent() != Some(handoff_root.as_path())
        || !path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with("launch-") && name.ends_with(".sock"))
    {
        bail!("workload environment socket is outside the native private runtime");
    }
    validate_private_runtime_directory(&runtime_root, owner_uid)?;
    validate_private_runtime_directory(&handoff_root, owner_uid)?;
    let metadata = fs::symlink_metadata(path).context("inspect workload environment socket")?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("workload environment socket has unsafe authority");
    }
    Ok(())
}

fn validate_private_runtime_directory(path: &Path, owner_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private runtime directory {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("private runtime directory has unsafe authority");
    }
    Ok(())
}

fn validate_dispatch_request(
    owner_uid: u32,
    workload_name: &str,
    cwd: &Path,
    launcher_pid: u32,
    environment_socket: &Path,
) -> Result<crate::policy_v2::ResolvedPolicy> {
    if owner_uid == 0 || launcher_pid == 0 {
        bail!("workload dispatch identity is invalid");
    }
    let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("workload owner account does not exist")?;
    validate_workload_cwd(cwd, owner_uid)?;
    validate_environment_socket_path(owner_uid, environment_socket)?;
    validate_root_owned_launcher(Path::new("/usr/bin/systemd-run"))?;
    let policy = crate::policy_store::load_resolved_policy_for_uid(owner_uid)?;
    if policy.mode != SystemMode::Strong {
        bail!("administrator policy does not enable strong supervision");
    }
    let workload = policy
        .workloads
        .get(workload_name)
        .with_context(|| format!("workload {workload_name} is not configured"))?;
    validate_workload_root_scope(cwd, &workload.workspace_roots)?;
    validate_root_owned_launcher(Path::new(&workload.launcher_path))?;
    if owner.uid.as_raw() != owner_uid {
        bail!("workload owner identity changed during dispatch");
    }
    Ok(policy)
}

fn select_sandbox_launch(
    policy: &ResolvedPolicy,
    workload: &ResolvedWorkload,
) -> Result<Option<SandboxLaunch>> {
    match workload.sandbox.mode {
        SandboxMode::None => Ok(None),
        SandboxMode::Auto if workload.sandbox.adapters.is_empty() => Ok(None),
        SandboxMode::Auto | SandboxMode::Required => {
            let name = workload
                .sandbox
                .adapters
                .first()
                .context("sandbox mode requires an approved adapter")?;
            let adapter = policy
                .sandbox_adapters
                .get(name)
                .context("resolved workload references an unknown sandbox adapter")?;
            let executable = PathBuf::from(&adapter.executable);
            validate_root_owned_launcher(&executable)?;
            Ok(Some(SandboxLaunch {
                executable,
                arguments: adapter.arguments.iter().map(OsString::from).collect(),
                argument_separator: adapter.argument_separator,
            }))
        }
    }
}

pub fn launch_via_pkexec(workload: &str, arguments: &[OsString]) -> Result<ExitStatus> {
    validate_identifier(workload, "workload")?;
    if nix::unistd::Uid::effective().is_root() {
        bail!("workload launcher must be invoked by the native user");
    }
    let (_, receipt) = crate::setup::current_installation()?;
    if receipt.mode != crate::setup::InstallMode::Strong {
        bail!("privileged workload launch requires a strong installation");
    }
    let cwd = std::env::current_dir().context("read workload launch directory")?;
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    let (listener, environment_socket, environment_frame) = create_environment_listener(owner_uid)?;
    let uid = owner_uid.to_string();
    let launcher_pid = std::process::id().to_string();
    let mut command = Command::new("/usr/bin/pkexec");
    command
        .arg(crate::setup::privileged_launcher_path())
        .args(["--uid", &uid, "--workload", workload])
        .arg("--cwd")
        .arg(cwd)
        .arg("--launcher-pid")
        .arg(launcher_pid)
        .arg("--environment-socket")
        .arg(&environment_socket)
        .arg("--")
        .args(arguments);
    let mut child = command
        .spawn()
        .context("start the privileged workload dispatcher")?;
    let handoff = send_environment_to_supervisor(&listener, &environment_frame, &mut child);
    let _ = fs::remove_file(&environment_socket);
    if let Err(error) = handoff {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("transfer workload environment to the privileged supervisor");
    }
    child
        .wait()
        .context("wait for the privileged workload boundary")
}

pub fn run_workload_alias(workload: &str, arguments: &[OsString]) -> Result<ExitStatus> {
    let resolved = crate::setup::resolve_current_workload_alias(workload)?;
    let (_, receipt) = crate::setup::current_installation()?;
    let (claim, probe) = crate::broker_client::active_claim_and_probe()?;
    match claim {
        crate::broker_protocol::LocalSessionClaim::Absent => match receipt.mode {
            crate::setup::InstallMode::Strong => launch_via_pkexec(workload, arguments),
            crate::setup::InstallMode::UserOnly => launch_user_only(workload, arguments),
        },
        crate::broker_protocol::LocalSessionClaim::Present { .. } => {
            match probe {
                crate::broker_protocol::BrokerSessionProbe::Verified { .. } => {}
                crate::broker_protocol::BrokerSessionProbe::NoSession
                | crate::broker_protocol::BrokerSessionProbe::Invalid { .. }
                | crate::broker_protocol::BrokerSessionProbe::Unavailable { .. } => {
                    bail!("existing workload admission is invalid or unavailable")
                }
            }
            match receipt.mode {
                crate::setup::InstallMode::Strong => {
                    validate_root_owned_launcher(Path::new(&resolved.launcher_path))?
                }
                crate::setup::InstallMode::UserOnly => validate_user_or_root_launcher(
                    Path::new(&resolved.launcher_path),
                    nix::unistd::Uid::effective().as_raw(),
                )?,
            }
            let error = Command::new(&resolved.launcher_path).args(arguments).exec();
            Err(error).context("replace nested workload alias with its configured launcher")
        }
    }
}

fn launch_user_only(workload_name: &str, arguments: &[OsString]) -> Result<ExitStatus> {
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 {
        bail!("user-only workload launch requires a native non-root user");
    }
    let policy = crate::policy_store::load_user_only_resolved_policy_for_uid(owner_uid)?;
    let workload = policy
        .workloads
        .get(workload_name)
        .with_context(|| format!("workload {workload_name} is not configured"))?;
    let profile = policy
        .authority_profiles
        .get(&workload.authority_profile)
        .context("user-only workload authority profile is unresolved")?;
    let launcher = Path::new(&workload.launcher_path);
    validate_user_or_root_launcher(launcher, owner_uid)?;
    let cwd = std::env::current_dir().context("read workload launch directory")?;
    validate_workload_cwd(&cwd, owner_uid)?;
    validate_workload_root_scope(&cwd, &workload.workspace_roots)?;
    let session_id = random_session_id()?;
    let (listener, socket, session_directory) =
        create_user_broker_listener(owner_uid, &session_id)?;
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective user account does not exist")?;
    let backend = crate::broker_backend::SystemCapabilityBackend::load_user(
        &crate::policy_store::user_policy_path(&user),
        owner_uid,
    )?;
    let session = crate::linux_admission::VerifiedLinuxSession {
        session_id: session_id.clone(),
        owner_uid,
        workload: workload_name.to_owned(),
        profile: workload.authority_profile.clone(),
        authority: session_authority_from_resolved(profile),
        cgroup: PathBuf::new(),
        expires_at_unix: lease_expiry(),
    };
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server_stop = std::sync::Arc::clone(&stop);
    let broker = thread::Builder::new()
        .name(format!("dev-auth-user-{session_id}"))
        .spawn(move || {
            crate::broker_server::serve_user_session_broker(listener, session, backend, server_stop)
        })
        .context("start user-only workload broker")?;

    let (installation_paths, _) = crate::setup::current_installation()?;
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| environment_name_is_safe(name))
        .collect::<BTreeMap<_, _>>();
    prepend_managed_bin_to_path(&mut environment, &installation_paths.bin_dir)?;
    apply_workload_command_safety(&mut environment);
    environment.insert(
        OsString::from(crate::broker_client::USER_BROKER_SOCKET_ENV),
        socket.as_os_str().to_os_string(),
    );
    environment.insert(
        OsString::from(crate::broker_client::USER_BROKER_SESSION_ENV),
        OsString::from(&session_id),
    );
    let mut agent_proxies = match start_agent_proxies(
        &user,
        &session_id,
        &workload.authority_profile,
        profile,
        &socket,
        false,
        &mut environment,
    ) {
        Ok(proxies) => proxies,
        Err(error) => {
            stop.store(true, std::sync::atomic::Ordering::Release);
            let _ = UnixStream::connect(&socket);
            let _ = broker.join();
            let _ = fs::remove_file(&socket);
            let _ = fs::remove_dir(&session_directory);
            return Err(error).context("start user-only broker SSH adapters");
        }
    };
    let sandbox = select_user_sandbox_launch(&policy, workload, owner_uid)?;
    let mut command = if let Some(sandbox) = sandbox {
        let executable = fs::canonicalize(std::env::current_exe()?)
            .context("resolve user-only sandbox probe executable")?;
        let sandbox_arguments = sandboxed_workload_arguments(
            &sandbox.arguments,
            sandbox.argument_separator,
            &executable,
            &session_id,
            workload_name,
            launcher,
            arguments,
        )?;
        let mut command = Command::new(sandbox.executable);
        command.args(sandbox_arguments);
        command
    } else {
        let mut command = Command::new(launcher);
        command.args(arguments);
        command
    };
    let status = command
        .env_clear()
        .envs(environment)
        .current_dir(cwd)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("run user-only admitted workload");

    stop_agent_proxies(&mut agent_proxies);
    stop.store(true, std::sync::atomic::Ordering::Release);
    let _ = UnixStream::connect(&socket);
    let broker_result = broker
        .join()
        .map_err(|_| anyhow::anyhow!("user-only broker thread panicked"))?;
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_dir(&session_directory);
    let status = status?;
    broker_result?;
    Ok(status)
}

pub fn run_root_dispatcher(
    owner_uid: u32,
    workload_name: &str,
    cwd: &Path,
    launcher_pid: u32,
    environment_socket: &Path,
    arguments: &[OsString],
) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("strong workload dispatch requires root");
    }
    let executable = crate::setup::validate_running_privileged_launcher()?;
    validate_identifier(workload_name, "workload")?;
    validate_pkexec_caller(owner_uid)?;
    validate_dispatch_request(
        owner_uid,
        workload_name,
        cwd,
        launcher_pid,
        environment_socket,
    )?;
    let session_id = random_session_id()?;
    let systemd_arguments = transient_service_arguments(&TransientServiceRequest {
        session_id: &session_id,
        owner_uid,
        workload: workload_name,
        cwd,
        launcher_pid,
        environment_socket,
        executable: &executable,
        arguments,
    })?;
    let error = Command::new("/usr/bin/systemd-run")
        .args(systemd_arguments)
        .exec();
    Err(error).context("replace privileged dispatcher with the transient workload service")
}

pub fn run_root_supervisor(
    owner_uid: u32,
    workload_name: &str,
    cwd: &Path,
    session_id: &str,
    launcher_pid: u32,
    environment_socket: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("strong workload supervision requires root");
    }
    validate_identifier(workload_name, "workload")?;
    validate_identifier(session_id, "session identifier")?;
    let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("workload owner account does not exist")?;
    let policy = validate_dispatch_request(
        owner_uid,
        workload_name,
        cwd,
        launcher_pid,
        environment_socket,
    )?;
    let workload = policy
        .workloads
        .get(workload_name)
        .context("validated workload is no longer resolved")?;
    let profile = policy
        .authority_profiles
        .get(&workload.authority_profile)
        .context("workload authority profile is unresolved")?;
    let mut environment =
        receive_workload_environment(owner_uid, launcher_pid, environment_socket)?;
    let cgroup = crate::linux_admission::current_workload_cgroup(session_id)?;
    let sandbox = select_sandbox_launch(&policy, workload)?;
    let mut agent_proxies = start_agent_proxies(
        &owner,
        session_id,
        &workload.authority_profile,
        profile,
        Path::new(crate::broker_client::SYSTEM_BROKER_SOCKET),
        true,
        &mut environment,
    )?;
    let gated = spawn_gated_child(GatedChildRequest {
        owner_uid,
        owner: &owner,
        session_id,
        workload: workload_name,
        cgroup: &cgroup,
        launcher: Path::new(&workload.launcher_path),
        cwd,
        arguments,
        environment,
        sandbox,
    });
    let mut gated = match gated {
        Ok(gated) => gated,
        Err(error) => {
            stop_agent_proxies(&mut agent_proxies);
            return Err(error);
        }
    };
    let mut registration = SessionRegistration {
        session_id: session_id.to_owned(),
        owner_uid,
        workload: workload_name.to_owned(),
        profile: workload.authority_profile.clone(),
        authority: session_authority_from_resolved(profile),
        cgroup: cgroup.clone(),
        expires_at_unix: lease_expiry(),
    };
    if let Err(error) = register_session(registration.clone()) {
        let _ = gated.child.kill();
        let _ = gated.child.wait();
        stop_agent_proxies(&mut agent_proxies);
        return Err(error).context("establish workload admission before launch");
    }

    if let Err(error) = nix::unistd::write(&gated.release, &[1]) {
        let _ = gated.child.kill();
        let _ = gated.child.wait();
        stop_agent_proxies(&mut agent_proxies);
        let _ = revoke_session(session_id);
        return Err(error).context("release the admitted workload process");
    }
    drop(gated.release);

    let result = supervise_child(&mut gated.child, &mut registration);
    stop_agent_proxies(&mut agent_proxies);
    let revoke_result = revoke_supervised_session(&mut registration);
    let status = result?;
    revoke_result?;
    Ok(status)
}

pub fn run_supervisor_child(
    session_id: &str,
    workload: &str,
    expected_cgroup: &Path,
    launcher: &Path,
    sandbox: Option<&SandboxLaunch>,
    gate_fd: RawFd,
    arguments: &[OsString],
) -> Result<()> {
    validate_identifier(session_id, "session identifier")?;
    validate_root_owned_launcher(launcher)?;
    wait_for_admission_gate(gate_fd)?;
    let claim = crate::linux_admission::local_session_claim()?;
    let expected_marker = format!("strong:{}", expected_cgroup.display());
    if claim
        != (crate::broker_protocol::LocalSessionClaim::Present {
            marker: expected_marker,
        })
    {
        bail!("supervised child is outside its registered workload boundary");
    }
    match crate::broker_client::probe_system_broker() {
        crate::broker_protocol::BrokerSessionProbe::Verified {
            session_id: verified,
            workload: verified_workload,
            ..
        } if verified == session_id && verified_workload == workload => {}
        crate::broker_protocol::BrokerSessionProbe::Verified { .. }
        | crate::broker_protocol::BrokerSessionProbe::NoSession
        | crate::broker_protocol::BrokerSessionProbe::Invalid { .. }
        | crate::broker_protocol::BrokerSessionProbe::Unavailable { .. } => {
            bail!("supervised child session is not admitted by the broker")
        }
    }
    if let Some(sandbox) = sandbox {
        validate_root_owned_launcher(&sandbox.executable)?;
        let executable = fs::canonicalize(std::env::current_exe()?)
            .context("resolve the sandbox probe executable")?;
        let sandbox_arguments = sandboxed_workload_arguments(
            &sandbox.arguments,
            sandbox.argument_separator,
            &executable,
            session_id,
            workload,
            launcher,
            arguments,
        )?;
        let error = Command::new(&sandbox.executable)
            .args(sandbox_arguments)
            .exec();
        return Err(error).context("replace supervisor gate with the sandbox adapter");
    }
    let error = Command::new(launcher).args(arguments).exec();
    Err(error).context("replace supervisor gate with the configured workload launcher")
}

pub fn run_sandbox_child(
    session_id: &str,
    workload_name: &str,
    launcher: &Path,
    arguments: &[OsString],
) -> Result<()> {
    validate_identifier(session_id, "session identifier")?;
    validate_identifier(workload_name, "workload")?;
    let (claim, probe) = crate::broker_client::active_claim_and_probe()?;
    if matches!(claim, crate::broker_protocol::LocalSessionClaim::Absent) {
        bail!("sandbox adapter is outside an admitted workload boundary");
    }
    let profile = require_sandbox_broker_identity(probe, session_id, workload_name)?;
    let owner_uid = nix::unistd::Uid::effective().as_raw();
    let (_, receipt) = crate::setup::current_installation()?;
    let policy = match receipt.mode {
        crate::setup::InstallMode::Strong => {
            crate::policy_store::load_resolved_policy_for_uid(owner_uid)?
        }
        crate::setup::InstallMode::UserOnly => {
            crate::policy_store::load_user_only_resolved_policy_for_uid(owner_uid)?
        }
    };
    let workload = policy
        .workloads
        .get(workload_name)
        .context("sandbox workload is no longer configured")?;
    if workload.authority_profile != profile || Path::new(&workload.launcher_path) != launcher {
        bail!("sandbox workload no longer matches its admitted identity");
    }
    match receipt.mode {
        crate::setup::InstallMode::Strong => validate_root_owned_launcher(launcher)?,
        crate::setup::InstallMode::UserOnly => validate_user_or_root_launcher(launcher, owner_uid)?,
    }
    let error = Command::new(launcher).args(arguments).exec();
    Err(error).context("replace sandbox probe with the configured workload launcher")
}

fn require_sandbox_broker_identity(
    probe: crate::broker_protocol::BrokerSessionProbe,
    session_id: &str,
    workload_name: &str,
) -> Result<String> {
    match probe {
        crate::broker_protocol::BrokerSessionProbe::Verified {
            session_id: verified,
            workload,
            profile,
        } if verified == session_id && workload == workload_name => Ok(profile),
        crate::broker_protocol::BrokerSessionProbe::Verified { .. } => {
            bail!("sandbox adapter crossed its admitted session boundary")
        }
        crate::broker_protocol::BrokerSessionProbe::NoSession => {
            bail!("sandbox adapter lost the admitted broker session")
        }
        crate::broker_protocol::BrokerSessionProbe::Invalid { .. } => {
            bail!("sandbox adapter did not preserve broker peer identity")
        }
        crate::broker_protocol::BrokerSessionProbe::Unavailable { .. } => {
            bail!("sandbox adapter cannot reach the admitted broker socket")
        }
    }
}

fn wait_for_admission_gate(gate_fd: RawFd) -> Result<()> {
    if gate_fd < 3 {
        bail!("supervisor child admission gate is invalid");
    }
    // SAFETY: the root supervisor created this pipe descriptor, explicitly kept
    // it across exec, and passed its exact numeric value as a private internal
    // argument. This process takes ownership exactly once and closes it on drop.
    let mut gate = unsafe { File::from_raw_fd(gate_fd) };
    let mut release = [0_u8; 1];
    gate.read_exact(&mut release)
        .context("wait for broker session registration")?;
    if release != [1] {
        bail!("supervisor child admission gate returned an invalid release");
    }
    Ok(())
}

fn validate_pkexec_caller(owner_uid: u32) -> Result<()> {
    let value =
        std::env::var("PKEXEC_UID").context("workload launch was not authorized by pkexec")?;
    let value = value
        .parse::<u32>()
        .context("pkexec caller identity is invalid")?;
    if value != owner_uid || owner_uid == 0 {
        bail!("pkexec caller does not match the requested workload owner");
    }
    Ok(())
}

fn validate_workload_cwd(cwd: &Path, owner_uid: u32) -> Result<()> {
    if !cwd.is_absolute() {
        bail!("workload current directory is not absolute");
    }
    let canonical = fs::canonicalize(cwd).context("resolve workload current directory")?;
    if canonical != cwd {
        bail!("workload current directory is not canonical");
    }
    let metadata = fs::symlink_metadata(cwd).context("inspect workload current directory")?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.uid() != owner_uid && metadata.uid() != 0)
        || metadata.mode() & 0o002 != 0
    {
        bail!("workload current directory has unsafe filesystem authority");
    }
    Ok(())
}

fn validate_workload_root_scope(
    cwd: &Path,
    workspace_roots: &[crate::policy_v2::ResolvedWorkspaceRoot],
) -> Result<()> {
    if workspace_roots.is_empty() {
        return Ok(());
    }
    for root in workspace_roots {
        let configured = Path::new(&root.path);
        let canonical = fs::canonicalize(configured)
            .with_context(|| format!("resolve workload root {}", configured.display()))?;
        if canonical != configured {
            bail!("configured workload root is not canonical");
        }
        if cwd == canonical || cwd.starts_with(&canonical) {
            return Ok(());
        }
    }
    bail!("workload current directory is outside its configured roots")
}

fn validate_root_owned_launcher(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("trusted workload launcher path is not absolute");
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect trusted launcher path {}", current.display()))?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            bail!("trusted workload launcher path is not root-owned immutable authority");
        }
    }
    let metadata = fs::symlink_metadata(path).context("inspect trusted workload launcher")?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o111 == 0 {
        bail!("trusted workload launcher is not an executable regular file");
    }
    Ok(())
}

fn validate_user_or_root_launcher(path: &Path, owner_uid: u32) -> Result<()> {
    if owner_uid == 0 || !path.is_absolute() {
        bail!("user-only workload launcher authority is invalid");
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect user-only launcher path {}", current.display()))?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != owner_uid)
            || metadata.mode() & 0o022 != 0
        {
            bail!("user-only launcher path is outside the documented same-user trust boundary");
        }
    }
    let metadata = fs::symlink_metadata(path).context("inspect user-only workload launcher")?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o111 == 0 {
        bail!("user-only workload launcher is not an executable regular file");
    }
    Ok(())
}

fn start_agent_proxies(
    owner: &nix::unistd::User,
    session_id: &str,
    profile_name: &str,
    profile: &ResolvedAuthorityProfile,
    broker_socket: &Path,
    drop_root_identity: bool,
    environment: &mut BTreeMap<OsString, OsString>,
) -> Result<Vec<AgentProxyProcess>> {
    let mut proxies = Vec::new();
    let result = (|| {
        if profile.signing_key.is_some() {
            let proxy = spawn_agent_proxy(
                owner,
                session_id,
                profile_name,
                crate::broker_protocol::SshOperationPurpose::GitSigning,
                broker_socket,
                drop_root_identity,
            )?;
            environment.insert(
                OsString::from(crate::broker_agent::SIGNING_AGENT_ENV),
                proxy.socket.as_os_str().to_os_string(),
            );
            proxies.push(proxy);
        }
        if !profile.ssh_keys.is_empty() {
            let proxy = spawn_agent_proxy(
                owner,
                session_id,
                profile_name,
                crate::broker_protocol::SshOperationPurpose::Authentication,
                broker_socket,
                drop_root_identity,
            )?;
            environment.insert(
                OsString::from("SSH_AUTH_SOCK"),
                proxy.socket.as_os_str().to_os_string(),
            );
            proxies.push(proxy);
        }
        Ok(())
    })();
    if let Err(error) = result {
        stop_agent_proxies(&mut proxies);
        return Err(error);
    }
    Ok(proxies)
}

fn spawn_agent_proxy(
    owner: &nix::unistd::User,
    session_id: &str,
    profile_name: &str,
    purpose: crate::broker_protocol::SshOperationPurpose,
    broker_socket: &Path,
    drop_root_identity: bool,
) -> Result<AgentProxyProcess> {
    let executable = fs::canonicalize(std::env::current_exe()?)
        .context("resolve installed broker SSH agent executable")?;
    let purpose_name = match purpose {
        crate::broker_protocol::SshOperationPurpose::GitSigning => "git-signing",
        crate::broker_protocol::SshOperationPurpose::Authentication => "authentication",
    };
    let socket = crate::broker_agent::agent_socket_path(owner.uid.as_raw(), session_id, purpose);
    let mut command = Command::new(executable);
    command
        .args([
            "agent-proxy",
            "--session",
            session_id,
            "--profile",
            profile_name,
        ])
        .args(["--purpose", purpose_name, "--socket"])
        .arg(&socket)
        .arg("--broker")
        .arg(broker_socket)
        .env_clear()
        .env("HOME", &owner.dir)
        .env("USER", &owner.name)
        .env("LOGNAME", &owner.name)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    if drop_root_identity {
        if !nix::unistd::Uid::effective().is_root() {
            bail!("only the strong root supervisor may drop broker SSH agent identity");
        }
        let username =
            CString::new(owner.name.as_bytes()).context("broker SSH agent username is invalid")?;
        let groups = nix::unistd::getgrouplist(&username, owner.gid)
            .context("resolve broker SSH agent supplementary groups")?;
        let owner_uid = owner.uid;
        let owner_gid = owner.gid;
        // SAFETY: this callback performs only async-signal-safe identity syscalls.
        // All path, account, group, and argument discovery completed above.
        unsafe {
            command.pre_exec(move || {
                nix::unistd::setgroups(&groups).map_err(std::io::Error::from)?;
                nix::unistd::setgid(owner_gid).map_err(std::io::Error::from)?;
                nix::unistd::setuid(owner_uid).map_err(std::io::Error::from)?;
                Ok(())
            });
        }
    }
    let mut child = command.spawn().context("start broker SSH agent process")?;
    let started = Instant::now();
    loop {
        match fs::symlink_metadata(&socket) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == owner.uid.as_raw()
                    && metadata.mode() & 0o077 == 0 =>
            {
                return Ok(AgentProxyProcess { child, socket })
            }
            Ok(_) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("broker SSH agent created an unsafe socket");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("inspect broker SSH agent socket");
            }
        }
        if let Some(status) = child.try_wait().context("poll broker SSH agent startup")? {
            bail!("broker SSH agent exited before readiness: {status}");
        }
        if started.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("broker SSH agent readiness timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn stop_agent_proxies(proxies: &mut Vec<AgentProxyProcess>) {
    for proxy in proxies.iter_mut() {
        let _ = proxy.child.kill();
        let _ = proxy.child.wait();
        let _ = fs::remove_file(&proxy.socket);
    }
    if let Some(session) = proxies.first().and_then(|proxy| proxy.socket.parent()) {
        let _ = fs::remove_dir(session);
    }
    proxies.clear();
}

fn create_user_broker_listener(
    owner_uid: u32,
    session_id: &str,
) -> Result<(UnixListener, PathBuf, PathBuf)> {
    validate_identifier(session_id, "session identifier")?;
    if owner_uid == 0 || owner_uid != nix::unistd::Uid::effective().as_raw() {
        bail!("user broker runtime owner is invalid");
    }
    let native_runtime = PathBuf::from(format!("/run/user/{owner_uid}"));
    validate_private_runtime_directory(&native_runtime, owner_uid)?;
    let runtime = native_runtime.join("dev-auth-v3");
    let sessions = runtime.join("user-sessions");
    for directory in [&runtime, &sessions] {
        match fs::symlink_metadata(directory) {
            Ok(_) => validate_private_runtime_directory(directory, owner_uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(directory) {
                    Ok(()) => validate_private_runtime_directory(directory, owner_uid)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        validate_private_runtime_directory(directory, owner_uid)?
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "create private user broker directory {}",
                                directory.display()
                            )
                        })
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect private user broker directory {}",
                        directory.display()
                    )
                })
            }
        }
    }
    let session = sessions.join(session_id);
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&session)
        .with_context(|| format!("reserve user broker session {}", session.display()))?;
    validate_private_runtime_directory(&session, owner_uid)?;
    let socket = session.join("broker.sock");
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = fs::remove_dir(&session);
            return Err(error).context("bind private user broker socket");
        }
    };
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .context("restrict private user broker socket")?;
    let metadata = fs::symlink_metadata(&socket).context("inspect private user broker socket")?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        let _ = fs::remove_file(&socket);
        let _ = fs::remove_dir(&session);
        bail!("private user broker socket has unsafe authority");
    }
    Ok((listener, socket, session))
}

fn select_user_sandbox_launch(
    policy: &ResolvedPolicy,
    workload: &ResolvedWorkload,
    owner_uid: u32,
) -> Result<Option<SandboxLaunch>> {
    match workload.sandbox.mode {
        SandboxMode::None => Ok(None),
        SandboxMode::Auto if workload.sandbox.adapters.is_empty() => Ok(None),
        SandboxMode::Auto | SandboxMode::Required => {
            let name = workload
                .sandbox
                .adapters
                .first()
                .context("sandbox mode requires an approved adapter")?;
            let adapter = policy
                .sandbox_adapters
                .get(name)
                .context("resolved workload references an unknown sandbox adapter")?;
            let executable = PathBuf::from(&adapter.executable);
            validate_user_or_root_launcher(&executable, owner_uid)?;
            Ok(Some(SandboxLaunch {
                executable,
                arguments: adapter.arguments.iter().map(OsString::from).collect(),
                argument_separator: adapter.argument_separator,
            }))
        }
    }
}

fn random_session_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .context("open kernel random source")?
        .read_exact(&mut bytes)
        .context("read workload session identifier")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn spawn_gated_child(mut request: GatedChildRequest<'_>) -> Result<GatedChild> {
    let executable = fs::canonicalize(std::env::current_exe()?)
        .context("resolve installed supervisor executable")?;
    let (paths, _) = crate::setup::current_installation()?;
    prepend_managed_bin_to_path(&mut request.environment, &paths.bin_dir)?;
    apply_workload_command_safety(&mut request.environment);
    let username =
        CString::new(request.owner.name.as_bytes()).context("workload username is invalid")?;
    let groups = nix::unistd::getgrouplist(&username, request.owner.gid)
        .context("resolve workload supplementary groups")?;
    let owner_gid = request.owner.gid;
    let owner_uid = nix::unistd::Uid::from_raw(request.owner_uid);
    let (gate_reader, gate_writer) =
        nix::unistd::pipe().context("create workload admission gate")?;
    let gate_read_fd = gate_reader.as_raw_fd();
    let gate_write_fd = gate_writer.as_raw_fd();
    nix::fcntl::fcntl(
        &gate_reader,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .context("retain workload admission gate across exec")?;
    let mut command = Command::new(executable);
    command
        .arg("supervisor-child")
        .arg(request.session_id)
        .arg(request.workload)
        .arg(request.cgroup)
        .arg(request.launcher)
        .arg("--sandbox")
        .arg(if request.sandbox.is_some() {
            "configured"
        } else {
            "none"
        });
    if let Some(sandbox) = &request.sandbox {
        command
            .arg(&sandbox.executable)
            .arg(if sandbox.argument_separator {
                "separator"
            } else {
                "direct"
            })
            .arg(sandbox.arguments.len().to_string())
            .args(&sandbox.arguments);
    }
    command
        .arg("--gate-fd")
        .arg(gate_read_fd.to_string())
        .arg("--")
        .args(request.arguments)
        .current_dir(request.cwd)
        .env_clear()
        .envs(request.environment)
        .env("HOME", &request.owner.dir)
        .env("USER", &request.owner.name)
        .env("LOGNAME", &request.owner.name);
    // SAFETY: this callback performs only async-signal-safe identity and close
    // syscalls between fork and exec. All discovery, allocation, validation, and
    // environment construction happened in the parent above. The supervisor-child
    // process reads the one-byte gate before probing or executing the workload.
    unsafe {
        command.pre_exec(move || {
            nix::libc::close(gate_write_fd);
            nix::unistd::setgroups(&groups).map_err(std::io::Error::from)?;
            nix::unistd::setgid(owner_gid).map_err(std::io::Error::from)?;
            nix::unistd::setuid(owner_uid).map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let child = command.spawn().context("start gated workload process")?;
    drop(gate_reader);
    Ok(GatedChild {
        child,
        release: gate_writer,
    })
}

fn sandboxed_workload_arguments(
    adapter_arguments: &[OsString],
    argument_separator: bool,
    dev_auth_executable: &Path,
    session_id: &str,
    workload: &str,
    launcher: &Path,
    workload_arguments: &[OsString],
) -> Result<Vec<OsString>> {
    validate_identifier(session_id, "session identifier")?;
    validate_identifier(workload, "workload")?;
    if !dev_auth_executable.is_absolute() || !launcher.is_absolute() {
        bail!("sandbox launch paths must be absolute");
    }
    let mut arguments = adapter_arguments.to_vec();
    if argument_separator {
        arguments.push(OsString::from("--"));
    }
    arguments.extend([
        dev_auth_executable.as_os_str().to_os_string(),
        OsString::from("sandbox-child"),
        OsString::from("--session"),
        OsString::from(session_id),
        OsString::from("--workload"),
        OsString::from(workload),
        OsString::from("--launcher"),
        launcher.as_os_str().to_os_string(),
        OsString::from("--"),
    ]);
    arguments.extend_from_slice(workload_arguments);
    Ok(arguments)
}

fn prepend_managed_bin_to_path(
    environment: &mut BTreeMap<OsString, OsString>,
    bin_dir: &Path,
) -> Result<()> {
    if !bin_dir.is_absolute() || bin_dir.as_os_str().as_bytes().contains(&b':') {
        bail!("managed launcher directory cannot be represented in PATH");
    }
    let mut path = bin_dir.as_os_str().as_bytes().to_vec();
    if let Some(existing) = environment.get(OsStr::new("PATH")) {
        path.push(b':');
        path.extend_from_slice(existing.as_bytes());
    }
    environment.insert(
        OsString::from("PATH"),
        OsStr::from_bytes(&path).to_os_string(),
    );
    Ok(())
}

fn apply_workload_command_safety(environment: &mut BTreeMap<OsString, OsString>) {
    for (name, value) in [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_ASKPASS", "/usr/bin/false"),
        ("SSH_ASKPASS", "/usr/bin/false"),
        ("GH_CONFIG_DIR", "/nonexistent/dev-auth-workload"),
        ("GH_PROMPT_DISABLED", "1"),
    ] {
        environment.insert(OsString::from(name), OsString::from(value));
    }
    let git_configuration = [
        ("credential.helper", ""),
        ("credential.helper", "/usr/bin/false"),
        ("credential.interactive", "never"),
        ("core.askPass", "/usr/bin/false"),
        ("core.sshCommand", "/usr/bin/false"),
        ("http.extraHeader", ""),
    ];
    environment.insert(
        OsString::from("GIT_CONFIG_COUNT"),
        OsString::from(git_configuration.len().to_string()),
    );
    for (index, (key, value)) in git_configuration.into_iter().enumerate() {
        environment.insert(
            OsString::from(format!("GIT_CONFIG_KEY_{index}")),
            OsString::from(key),
        );
        environment.insert(
            OsString::from(format!("GIT_CONFIG_VALUE_{index}")),
            OsString::from(value),
        );
    }
}

fn environment_name_is_safe(name: &OsStr) -> bool {
    let name = name.as_bytes();
    if name.is_empty()
        || name.contains(&b'\0')
        || name.starts_with(b"DEV_AUTH_")
        || name.starts_with(b"LD_")
        || name.starts_with(b"DYLD_")
    {
        return false;
    }
    ![
        b"GH_TOKEN".as_slice(),
        b"GITHUB_TOKEN",
        b"OP_SERVICE_ACCOUNT_TOKEN",
        b"SSH_AUTH_SOCK",
        b"GIT_ASKPASS",
        b"SSH_ASKPASS",
        b"GIT_SSH",
        b"GIT_SSH_COMMAND",
        b"PYTHONPATH",
        b"PERL5LIB",
        b"RUBYLIB",
    ]
    .contains(&name)
}

fn register_session(registration: SessionRegistration) -> Result<()> {
    match crate::broker_client::control_request_system(ControlRequest::Register {
        session: Box::new(registration),
    })? {
        ControlResponse::Accepted => Ok(()),
        ControlResponse::Denied { message } => bail!(message),
        ControlResponse::Revoked { .. } => {
            bail!("broker returned an invalid registration response")
        }
    }
}

fn renew_session(session_id: &str) -> Result<()> {
    match crate::broker_client::control_request_system(ControlRequest::Renew {
        session_id: session_id.to_owned(),
        expires_at_unix: lease_expiry(),
    })? {
        ControlResponse::Accepted => Ok(()),
        ControlResponse::Denied { message } => bail!(message),
        ControlResponse::Revoked { .. } => bail!("broker returned an invalid renewal response"),
    }
}

fn revoke_session(session_id: &str) -> Result<()> {
    match crate::broker_client::control_request_system(ControlRequest::Revoke {
        session_id: session_id.to_owned(),
    })? {
        ControlResponse::Revoked { existed: true } => Ok(()),
        ControlResponse::Revoked { existed: false } => bail!("broker session was already absent"),
        ControlResponse::Denied { message } => bail!(message),
        ControlResponse::Accepted => bail!("broker returned an invalid revocation response"),
    }
}

fn supervise_child(
    child: &mut Child,
    registration: &mut SessionRegistration,
) -> Result<ExitStatus> {
    let mut next_renewal = Instant::now() + Duration::from_secs(SESSION_RENEW_SECONDS);
    loop {
        if let Some(status) = child.try_wait().context("poll supervised workload")? {
            return Ok(status);
        }
        if Instant::now() >= next_renewal {
            if let Err(error) = renew_or_reassociate(registration) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("renew workload admission lease");
            }
            next_renewal = Instant::now() + Duration::from_secs(SESSION_RENEW_SECONDS);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn renew_or_reassociate(registration: &mut SessionRegistration) -> Result<()> {
    renew_or_reassociate_with(
        registration,
        Duration::from_secs(SESSION_REASSOCIATION_SECONDS),
        renew_session,
        register_session,
    )
}

fn renew_or_reassociate_with<Renew, Register>(
    registration: &mut SessionRegistration,
    timeout: Duration,
    mut renew: Renew,
    mut register: Register,
) -> Result<()>
where
    Renew: FnMut(&str) -> Result<()>,
    Register: FnMut(SessionRegistration) -> Result<()>,
{
    let deadline = Instant::now() + timeout;
    loop {
        registration.expires_at_unix = lease_expiry();
        if renew(&registration.session_id).is_ok() {
            return Ok(());
        }
        if register(registration.clone()).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("broker did not re-associate the retained workload boundary");
        }
        thread::sleep(Duration::from_millis(SESSION_REASSOCIATION_RETRY_MILLIS));
    }
}

fn revoke_supervised_session(registration: &mut SessionRegistration) -> Result<()> {
    if revoke_session(&registration.session_id).is_ok() {
        return Ok(());
    }
    renew_or_reassociate(registration)
        .context("re-associate workload boundary before terminal revocation")?;
    revoke_session(&registration.session_id)
}

fn lease_expiry() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp() + SESSION_LEASE_SECONDS
}

fn validate_identifier(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        bail!("{description} is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_registration() -> SessionRegistration {
        SessionRegistration {
            session_id: "a".repeat(32),
            owner_uid: 1000,
            workload: "codex".into(),
            profile: "automation".into(),
            authority: crate::linux_admission::SessionAuthorityGrant {
                github: None,
                signing: None,
                ssh: Vec::new(),
            },
            cgroup: "/sys/fs/cgroup/system.slice/dev-auth-workload-a.scope".into(),
            expires_at_unix: 1,
        }
    }

    #[test]
    fn retained_workload_boundary_reassociates_after_broker_restart() {
        let mut registration = test_session_registration();
        let mut renewals = 0;
        let mut registrations = 0;

        renew_or_reassociate_with(
            &mut registration,
            Duration::ZERO,
            |_| {
                renewals += 1;
                bail!("session was lost with the prior broker")
            },
            |candidate| {
                registrations += 1;
                assert_eq!(candidate.session_id, "a".repeat(32));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(renewals, 1);
        assert_eq!(registrations, 1);
        assert!(registration.expires_at_unix > 1);
    }

    #[test]
    fn transient_lost_response_retries_renewal_without_duplicate_admission() {
        let mut registration = test_session_registration();
        let mut renewals = 0;
        let mut registrations = 0;

        renew_or_reassociate_with(
            &mut registration,
            Duration::from_secs(1),
            |_| {
                renewals += 1;
                if renewals == 1 {
                    bail!("first response was lost")
                }
                Ok(())
            },
            |_| {
                registrations += 1;
                bail!("the original broker still owns the session")
            },
        )
        .unwrap();

        assert_eq!(renewals, 2);
        assert_eq!(registrations, 1);
    }

    #[test]
    fn unprovable_restart_fails_after_the_bounded_reassociation_window() {
        let mut registration = test_session_registration();
        let error = renew_or_reassociate_with(
            &mut registration,
            Duration::ZERO,
            |_| bail!("broker unavailable"),
            |_| bail!("boundary rejected"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("did not re-associate the retained workload boundary"));
    }

    #[test]
    fn workload_environment_removes_auth_and_loader_injection_but_keeps_ui_settings() {
        for denied in [
            "DEV_AUTH_SESSION",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "SSH_AUTH_SOCK",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "PYTHONPATH",
            "PERL5LIB",
            "RUBYLIB",
        ] {
            assert!(!environment_name_is_safe(OsStr::new(denied)));
        }
        for preserved in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "DBUS_SESSION_BUS_ADDRESS",
            "GIT_EDITOR",
            "GIT_PAGER",
            "TERM",
            "PATH",
        ] {
            assert!(environment_name_is_safe(OsStr::new(preserved)));
        }
    }

    #[test]
    fn workload_path_always_prefers_the_receipted_same_name_launchers() {
        let mut environment =
            BTreeMap::from([(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))]);
        prepend_managed_bin_to_path(&mut environment, Path::new("/opt/dev-auth/bin")).unwrap();
        assert_eq!(
            environment.get(OsStr::new("PATH")),
            Some(&OsString::from("/opt/dev-auth/bin:/usr/bin:/bin"))
        );
        assert!(
            prepend_managed_bin_to_path(&mut environment, Path::new("/opt/dev-auth:unsafe"))
                .is_err()
        );
    }

    #[test]
    fn workload_launch_directory_must_be_inside_a_canonical_configured_root() {
        let allowed = tempfile::tempdir().unwrap();
        let nested = allowed.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let roots = vec![crate::policy_v2::ResolvedWorkspaceRoot {
            system_cap: "source".to_owned(),
            path: allowed.path().display().to_string(),
            access: crate::policy_v2::WorkspaceAccess::ReadWrite,
        }];

        assert!(validate_workload_root_scope(allowed.path(), &roots).is_ok());
        assert!(validate_workload_root_scope(&nested, &roots).is_ok());
        assert!(validate_workload_root_scope(outside.path(), &roots).is_err());
        assert!(validate_workload_root_scope(outside.path(), &[]).is_ok());

        let parent = tempfile::tempdir().unwrap();
        let alias = parent.path().join("workspace-alias");
        std::os::unix::fs::symlink(allowed.path(), &alias).unwrap();
        let aliased = vec![crate::policy_v2::ResolvedWorkspaceRoot {
            system_cap: "source".to_owned(),
            path: alias.display().to_string(),
            access: crate::policy_v2::WorkspaceAccess::ReadOnly,
        }];
        assert!(validate_workload_root_scope(allowed.path(), &aliased).is_err());
    }

    #[test]
    fn direct_native_tools_inside_a_workload_cannot_fall_back_to_human_credentials() {
        let mut environment = BTreeMap::from([
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/home/user/.gitconfig"),
            ),
            (
                OsString::from("GH_CONFIG_DIR"),
                OsString::from("/home/user/.config/gh"),
            ),
        ]);
        apply_workload_command_safety(&mut environment);
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_GLOBAL")),
            Some(&OsString::from("/dev/null"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_NOSYSTEM")),
            Some(&OsString::from("1"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_ASKPASS")),
            Some(&OsString::from("/usr/bin/false"))
        );
        assert_eq!(
            environment.get(OsStr::new("GH_CONFIG_DIR")),
            Some(&OsString::from("/nonexistent/dev-auth-workload"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_COUNT")),
            Some(&OsString::from("6"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_KEY_0")),
            Some(&OsString::from("credential.helper"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_VALUE_1")),
            Some(&OsString::from("/usr/bin/false"))
        );
    }

    #[test]
    fn direct_native_git_cannot_inherit_a_repository_credential_helper() {
        let root = tempfile::tempdir().unwrap();
        let git_dir = root.path().join(".git");
        assert!(Command::new("/usr/bin/git")
            .args(["init", "--quiet"])
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", "/usr/bin:/bin")
            .status()
            .unwrap()
            .success());
        let marker = root.path().join("human-helper-ran");
        let helper = root.path().join("human-helper");
        fs::write(
            &helper,
            format!(
                "#!/usr/bin/sh\n: > '{}'\nprintf 'username=human\\npassword=human\\n'\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            git_dir.join("config"),
            format!(
                "[core]\n\trepositoryformatversion = 0\n[credential]\n\thelper = !{}\n",
                helper.display()
            ),
        )
        .unwrap();

        let invoke = |safe: bool| {
            let mut command = Command::new("/usr/bin/git");
            command
                .args(["credential", "fill"])
                .current_dir(root.path())
                .env_clear()
                .env("HOME", root.path())
                .env("PATH", "/usr/bin:/bin")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if safe {
                let mut environment = BTreeMap::new();
                apply_workload_command_safety(&mut environment);
                command.envs(environment);
            }
            let mut child = command.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"protocol=https\nhost=github.com\n\n")
                .unwrap();
            child.wait().unwrap()
        };

        assert!(invoke(false).success());
        assert!(marker.is_file());
        fs::remove_file(&marker).unwrap();
        assert!(!invoke(true).success());
        assert!(!marker.exists());
    }

    #[test]
    fn session_identifiers_and_root_owned_launchers_are_exact() {
        let session = random_session_id().unwrap();
        assert_eq!(session.len(), 32);
        assert!(validate_identifier(&session, "session").is_ok());
        assert!(validate_identifier("../escape", "session").is_err());
        assert!(validate_root_owned_launcher(Path::new("/usr/bin/true")).is_ok());

        let root = tempfile::tempdir().unwrap();
        let launcher = root.path().join("launcher");
        fs::write(&launcher, b"not trusted").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_root_owned_launcher(&launcher).is_err());
    }

    #[test]
    fn workload_environment_frame_preserves_public_non_utf8_values_without_auth_material() {
        let mut environment = BTreeMap::from([
            (
                OsString::from("GIT_EDITOR"),
                OsString::from("code-insiders --wait"),
            ),
            (
                OsString::from("DISPLAY"),
                OsStr::from_bytes(b":0-\xff").to_os_string(),
            ),
            (OsString::from("GH_TOKEN"), OsString::from("must-not-cross")),
        ]);
        environment.retain(|name, _| environment_name_is_safe(name));

        let frame = encode_workload_environment(&environment).unwrap();
        assert!(!frame
            .windows(b"must-not-cross".len())
            .any(|window| window == b"must-not-cross"));
        assert_eq!(decode_workload_environment(&frame).unwrap(), environment);

        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_workload_environment(&trailing).is_err());
    }

    #[test]
    fn transient_systemd_boundary_is_exact_and_kills_the_whole_workload_on_supervisor_exit() {
        let arguments = transient_service_arguments(&TransientServiceRequest {
            session_id: "0123456789abcdef0123456789abcdef",
            owner_uid: 1000,
            workload: "codex",
            cwd: Path::new("/home/example/work"),
            launcher_pid: 1234,
            environment_socket: Path::new("/run/user/1000/dev-auth-v3/launch.sock"),
            executable: Path::new("/usr/local/lib/dev-auth/versions/0.3.0/dev-auth"),
            arguments: &[OsString::from("--example")],
        })
        .unwrap();
        let rendered = arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(rendered.iter().any(|value| value == "--wait"));
        assert!(rendered.iter().any(|value| value == "--pipe"));
        assert!(rendered
            .iter()
            .any(|value| value == "--property=KillMode=control-group"));
        assert!(rendered
            .iter()
            .any(|value| value == "--property=SendSIGKILL=yes"));
        assert!(rendered
            .iter()
            .any(|value| value == "--unit=dev-auth-workload-0123456789abcdef0123456789abcdef"));
        assert_eq!(rendered.last().map(AsRef::as_ref), Some("--example"));
    }

    #[test]
    fn workload_exec_gate_cannot_open_before_session_registration_release() {
        use std::os::fd::IntoRawFd;
        use std::sync::mpsc;

        let (reader, writer) = nix::unistd::pipe().unwrap();
        let reader = reader.into_raw_fd();
        let (sender, receiver) = mpsc::channel();
        let waiter = thread::spawn(move || {
            sender.send(wait_for_admission_gate(reader)).unwrap();
        });
        thread::sleep(Duration::from_millis(25));
        assert!(receiver.try_recv().is_err());
        nix::unistd::write(&writer, &[1]).unwrap();
        drop(writer);
        receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn sandbox_adapter_wraps_the_internal_probe_without_rewriting_workload_arguments() {
        let arguments = sandboxed_workload_arguments(
            &["--unshare-all".into(), "--share-net".into()],
            true,
            Path::new("/usr/local/lib/dev-auth/versions/0.3.0/dev-auth"),
            "0123456789abcdef0123456789abcdef",
            "codex",
            Path::new("/opt/codex/bin/codex"),
            &[OsString::from("--future-flag"), OsString::from("value")],
        )
        .unwrap();
        assert_eq!(
            arguments,
            [
                OsString::from("--unshare-all"),
                OsString::from("--share-net"),
                OsString::from("--"),
                OsString::from("/usr/local/lib/dev-auth/versions/0.3.0/dev-auth"),
                OsString::from("sandbox-child"),
                OsString::from("--session"),
                OsString::from("0123456789abcdef0123456789abcdef"),
                OsString::from("--workload"),
                OsString::from("codex"),
                OsString::from("--launcher"),
                OsString::from("/opt/codex/bin/codex"),
                OsString::from("--"),
                OsString::from("--future-flag"),
                OsString::from("value"),
            ]
        );
    }

    #[test]
    fn sandbox_failures_identify_the_broken_containment_property() {
        let session = "0123456789abcdef0123456789abcdef";
        for (probe, expected) in [
            (
                crate::broker_protocol::BrokerSessionProbe::Unavailable {
                    reason: "socket hidden".into(),
                },
                "cannot reach the admitted broker socket",
            ),
            (
                crate::broker_protocol::BrokerSessionProbe::Invalid {
                    reason: "peer mismatch".into(),
                },
                "did not preserve broker peer identity",
            ),
            (
                crate::broker_protocol::BrokerSessionProbe::NoSession,
                "lost the admitted broker session",
            ),
            (
                crate::broker_protocol::BrokerSessionProbe::Verified {
                    session_id: "fedcba9876543210fedcba9876543210".into(),
                    workload: "codex".into(),
                    profile: "automation".into(),
                },
                "crossed its admitted session boundary",
            ),
        ] {
            let error = require_sandbox_broker_identity(probe, session, "codex").unwrap_err();
            assert!(error.to_string().contains(expected));
        }
        assert_eq!(
            require_sandbox_broker_identity(
                crate::broker_protocol::BrokerSessionProbe::Verified {
                    session_id: session.into(),
                    workload: "codex".into(),
                    profile: "automation".into(),
                },
                session,
                "codex",
            )
            .unwrap(),
            "automation"
        );
    }
}
