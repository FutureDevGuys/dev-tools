//! Policy-owned plans run in one already-admitted native execution boundary.
//! A sealed descriptor supplies the plan to a private same-product worker; it
//! is never exposed through argv, environment, or a mutable temporary file.

use super::policy::{ExecutionPlan, ExitPolicy, PlanStreamMode, Policy, RunAsIdentity};
use super::{Authority, Failure};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

const LIMIT: usize = 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    plan: ExecutionPlan,
    deadline_milliseconds: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    terminal: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    null_device: Option<NullDevice>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NullDevice {
    descriptor: i32,
    device: u64,
    inode: u64,
}

pub(super) struct PreparedGraph {
    pub snapshot: OwnedFd,
    pub null_device: Option<OwnedFd>,
}

fn is_false(value: &bool) -> bool {
    !value
}

pub(super) fn select(
    policy: &Policy,
    granted: &Authority,
    selected: &Authority,
) -> Result<ExecutionPlan, Failure> {
    if !granted.permits(selected) {
        return Err(Failure::AuthorityDenied);
    }
    let plan = match selected {
        Authority::ExactPlan { sha256 } => policy.plans.get(sha256),
        Authority::Typed { operations } if operations.len() == 1 => {
            policy.operations.get(&operations[0])
        }
        _ => None,
    }
    .ok_or(Failure::AuthorityDenied)?;
    plan.validate()?;
    Ok(plan.clone())
}

pub(super) fn prepare(
    plan: ExecutionPlan,
    deadline: Duration,
    terminal: bool,
) -> Result<PreparedGraph, Failure> {
    plan.validate()?;
    if deadline > dev_tools_privilege_session::linux::MAX_BOOT_DEADLINE {
        return Err(Failure::InvalidRequest);
    }
    let null_device = plan
        .requires_null_device()
        .then(prepare_host_null_device)
        .transpose()?;
    let bytes = serde_json::to_vec(&Snapshot {
        schema: "dev-auth-plan-worker-v1".into(),
        plan,
        deadline_milliseconds: u64::try_from(deadline.as_millis())
            .map_err(|_| Failure::InvalidRequest)?,
        terminal,
        null_device: null_device.as_ref().map(|(_, identity)| NullDevice {
            descriptor: identity.descriptor,
            device: identity.device,
            inode: identity.inode,
        }),
    })
    .map_err(|_| Failure::InvalidRequest)?;
    if bytes.len() > LIMIT {
        return Err(Failure::InvalidRequest);
    }
    let mut file = File::from(
        rustix::fs::memfd_create(
            "dev-auth-plan",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| Failure::NativeUnavailable)?,
    );
    file.write_all(&bytes)
        .and_then(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|_| Failure::RuntimeFailure)?;
    rustix::fs::fcntl_add_seals(&file, required_seals()).map_err(|_| Failure::NativeUnavailable)?;
    Ok(PreparedGraph {
        snapshot: file.into(),
        null_device: null_device.map(|(descriptor, _)| descriptor),
    })
}

/// Retain the host facility before the admitted worker enters caller mounts.
fn prepare_host_null_device() -> Result<(OwnedFd, NullDevice), Failure> {
    let directory = std::fs::symlink_metadata("/dev").map_err(|_| Failure::NativeUnavailable)?;
    let expected =
        std::fs::symlink_metadata("/dev/null").map_err(|_| Failure::NativeUnavailable)?;
    if !directory.is_dir()
        || directory.uid() != 0
        || directory.mode() & 0o022 != 0
        || !is_native_null(&expected)
    {
        return Err(Failure::AuthorityDenied);
    }
    let file = File::from(
        rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| Failure::NativeUnavailable)?,
    );
    let observed = file.metadata().map_err(|_| Failure::NativeUnavailable)?;
    if !is_native_null(&observed)
        || observed.dev() != expected.dev()
        || observed.ino() != expected.ino()
    {
        return Err(Failure::AuthorityDenied);
    }
    let descriptor =
        rustix::io::fcntl_dupfd_cloexec(&file, 3).map_err(|_| Failure::NativeUnavailable)?;
    let identity = NullDevice {
        descriptor: descriptor.as_raw_fd(),
        device: observed.dev(),
        inode: observed.ino(),
    };
    Ok((descriptor, identity))
}

fn is_native_null(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_char_device()
        && metadata.uid() == 0
        && metadata.rdev() == nix::libc::makedev(1, 3)
}

fn take_null_device(
    identity: Option<&NullDevice>,
    snapshot_descriptor: i32,
) -> Result<Option<File>, Failure> {
    let Some(identity) = identity else {
        return Ok(None);
    };
    if identity.descriptor < 3 || identity.descriptor == snapshot_descriptor {
        return Err(Failure::InvalidRequest);
    }
    // SAFETY: the sealed root-prepared snapshot names this exclusively owned
    // inherited descriptor, distinct from stdio and the snapshot itself. F_GETFD
    // verifies it is open before ownership is adopted; this worker is single-
    // threaded and creates no descriptor between that check and adoption.
    let file = unsafe {
        if nix::libc::fcntl(identity.descriptor, nix::libc::F_GETFD) < 0 {
            return Err(Failure::AuthorityDenied);
        }
        File::from(OwnedFd::from_raw_fd(identity.descriptor))
    };
    let observed = file.metadata().map_err(|_| Failure::AuthorityDenied)?;
    if !is_native_null(&observed)
        || observed.dev() != identity.device
        || observed.ino() != identity.inode
    {
        return Err(Failure::AuthorityDenied);
    }
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| Failure::NativeUnavailable)?;
    Ok(Some(file))
}

fn required_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE
}

#[doc(hidden)]
pub fn run_worker() -> i32 {
    if !nix::unistd::getuid().is_root()
        || !nix::unistd::geteuid().is_root()
        || nix::unistd::getgid().as_raw() != 0
        || nix::unistd::getegid().as_raw() != 0
    {
        return 4;
    }
    let mut arguments = std::env::args_os().skip(2);
    let Some(descriptor) = arguments
        .next()
        .and_then(|value| value.to_str().and_then(|value| value.parse::<i32>().ok()))
        .filter(|fd| *fd >= 3)
    else {
        return 2;
    };
    if arguments.next().is_some() {
        return 2;
    }
    // SAFETY: F_GETFD checks the integer before making a Rust descriptor owner.
    // The private worker exclusively owns descriptors inherited from its parent.
    if unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) } < 0 {
        return 4;
    }
    let file = File::from(unsafe { OwnedFd::from_raw_fd(descriptor) });
    if !rustix::fs::fcntl_get_seals(&file).is_ok_and(|flags| flags.contains(required_seals())) {
        return 4;
    }
    // Workload-directed signals reach every native job member. Keep this
    // trusted graph coordinator alive; each payload restores the original mask.
    // SIGKILL/STOP and the external job deadline remain kernel-authoritative.
    let mut original: nix::libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut blocked: nix::libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: native initialized mask buffers are valid for these scalar mask
    // syscalls, before this private single-threaded worker spawns any payload.
    if unsafe { nix::libc::sigfillset(&mut blocked) } != 0
        || unsafe { nix::libc::sigdelset(&mut blocked, nix::libc::SIGTSTP) } != 0
        || unsafe { nix::libc::sigdelset(&mut blocked, nix::libc::SIGCONT) } != 0
        || unsafe { nix::libc::pthread_sigmask(nix::libc::SIG_BLOCK, &blocked, &mut original) } != 0
    {
        return 125;
    }
    match read_and_run(file, original) {
        Ok(status) => native_status_code(status),
        Err(_) => {
            eprintln!("dev-auth: approved command graph failed");
            125
        }
    }
}

fn read_and_run(mut file: File, original_mask: nix::libc::sigset_t) -> Result<ExitStatus, Failure> {
    let snapshot_descriptor = file.as_raw_fd();
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::InvalidRequest)?;
    drop(file);
    if bytes.len() > LIMIT {
        return Err(Failure::InvalidRequest);
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidRequest)?;
    if snapshot.schema != "dev-auth-plan-worker-v1" {
        return Err(Failure::InvalidRequest);
    }
    snapshot.plan.validate()?;
    let needs_null_device = snapshot.plan.requires_null_device();
    if needs_null_device != snapshot.null_device.is_some() {
        return Err(Failure::InvalidRequest);
    }
    let null_device = take_null_device(snapshot.null_device.as_ref(), snapshot_descriptor)?;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    if snapshot.plan.nodes.iter().any(|node| node.run_as.is_some()) {
        return Err(Failure::NativeUnavailable);
    }
    let deadline = Duration::from_millis(snapshot.deadline_milliseconds);
    let held = snapshot
        .plan
        .nodes
        .iter()
        .map(|node| {
            dev_tools_command::HeldExecutable::open(std::path::Path::new(&node.program))
                .map_err(|_| Failure::AuthorityDenied)
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let dependencies = snapshot.plan.dependencies()?;
    let commands = snapshot
        .plan
        .nodes
        .iter()
        .zip(&held)
        .zip(dependencies)
        .map(|((node, executable), dependencies)| {
            let mut command = executable
                .command(&node.program)
                .map_err(|_| Failure::AuthorityDenied)?;
            command
                .args(&node.arguments)
                .current_dir(&node.working_directory)
                .env_clear()
                .envs(node.environment.iter().map(|(key, value)| (key, value)))
                .stdin(selected_stream(node.stdin, null_device.as_ref())?)
                .stdout(selected_stream(node.stdout, null_device.as_ref())?)
                .stderr(selected_stream(node.stderr, null_device.as_ref())?);
            let run_as = node.run_as.clone();
            // SAFETY: validation bounds these captured host IDs/groups before
            // spawning, and their owned allocation stays live through exec.
            // The single-threaded payload child performs only raw Linux identity
            // syscalls, then restores the by-value mask; it allocates nothing,
            // performs no NSS lookup and does not change the root coordinator.
            unsafe {
                command.pre_exec(move || {
                    apply_child_identity_and_mask(run_as.as_ref(), &original_mask)
                });
            }
            Ok(dev_tools_command::CommandGraphNode {
                command: command.into(),
                dependencies,
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let policy = match snapshot.plan.exit_policy {
        ExitPolicy::Last => dev_tools_command::GraphExitPolicy::Last,
        ExitPolicy::All => dev_tools_command::GraphExitPolicy::All,
        ExitPolicy::Pipefail => dev_tools_command::GraphExitPolicy::Pipefail,
    };
    let continue_running =
        || dev_tools_privilege_session::linux::boot_time().is_ok_and(|now| now < deadline);
    let output = if snapshot.terminal {
        dev_tools_command::run_prepared_terminal_command_graph(
            commands,
            policy,
            dev_tools_command::TerminalGraphSignalMask::PreservePrepared,
            continue_running,
        )
    } else {
        dev_tools_command::run_prepared_command_graph(commands, policy, continue_running)
    }
    .map_err(|_| Failure::RuntimeFailure)?;
    Ok(output.status)
}

/// Apply the already-approved payload identity and original signal mask.
///
/// # Safety
/// Call only in a freshly forked payload child before exec, with validated
/// numeric IDs/groups and live group storage. The original mask belongs to the
/// product caller. This must never change the coordinator's identity or mask.
unsafe fn apply_child_identity_and_mask(
    run_as: Option<&RunAsIdentity>,
    original_mask: &nix::libc::sigset_t,
) -> std::io::Result<()> {
    // SAFETY: the caller guarantees child-only execution, validated native IDs
    // and live owned group storage. Only raw syscalls run here; no allocation,
    // NSS lookup or process-wide libc credential synchronization occurs.
    unsafe {
        if let Some(identity) = run_as {
            if nix::libc::syscall(
                nix::libc::SYS_setgroups,
                identity.supplementary_groups.len(),
                identity.supplementary_groups.as_ptr(),
            ) < 0
                || nix::libc::syscall(nix::libc::SYS_setgid, identity.gid) < 0
                || nix::libc::syscall(nix::libc::SYS_setuid, identity.uid) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        if nix::libc::sigprocmask(nix::libc::SIG_SETMASK, original_mask, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn selected_stream(
    selection: Option<PlanStreamMode>,
    null_device: Option<&File>,
) -> Result<Stdio, Failure> {
    match selection {
        None | Some(PlanStreamMode::Inherit) => Ok(Stdio::inherit()),
        Some(PlanStreamMode::Null) => Ok(Stdio::from(
            null_device
                .ok_or(Failure::InvalidRequest)?
                .try_clone()
                .map_err(|_| Failure::NativeUnavailable)?,
        )),
    }
}

/// The shared runner has already joined every owned direct process group.
/// Preserve its aggregate native signal instead of manufacturing a numeric exit.
fn native_status_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    let Some(signal) = status
        .signal()
        .filter(|signal| *signal > 0 && *signal <= 64)
    else {
        return 125;
    };
    // SAFETY: these raw operations use initialized local native signal sets.
    // No child execution remains owned by this private worker; only its own
    // disposition/mask are selected before sending the aggregate signal to self.
    unsafe {
        if signal != nix::libc::SIGKILL && signal != nix::libc::SIGSTOP {
            let mut action: nix::libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = nix::libc::SIG_DFL;
            if nix::libc::sigemptyset(&mut action.sa_mask) != 0
                || nix::libc::sigaction(signal, &action, std::ptr::null_mut()) != 0
            {
                return 125;
            }
        }
        let mut selected: nix::libc::sigset_t = std::mem::zeroed();
        if nix::libc::sigemptyset(&mut selected) != 0
            || nix::libc::sigaddset(&mut selected, signal) != 0
            || nix::libc::sigprocmask(nix::libc::SIG_UNBLOCK, &selected, std::ptr::null_mut()) != 0
            || nix::libc::kill(nix::libc::getpid(), signal) != 0
        {
            return 125;
        }
        // Signal delivery to self occurs at the syscall boundary. If a caller
        // violates exclusive disposition ownership, fail rather than claim it.
        nix::libc::_exit(125)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn selected_identity_syscall_failure_prevents_payload_exec() {
        use std::process::Child;
        use std::time::Instant;

        fn observe_until(
            child: &mut Child,
            deadline: Instant,
        ) -> std::io::Result<Option<ExitStatus>> {
            loop {
                if let Some(status) = child.try_wait()? {
                    return Ok(Some(status));
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
        }

        fn cleanup_until(child: &mut Child, deadline: Instant) -> String {
            let kill = child.kill();
            match observe_until(child, deadline) {
                Ok(Some(status)) => format!("kill={kill:?}; terminal status reaped={status:?}"),
                Ok(None) => format!("kill={kill:?}; cleanup unproved at fixed deadline"),
                Err(error) => format!("kill={kill:?}; cleanup unproved: try_wait={error:?}"),
            }
        }

        // Native capget v3 uses one two-u32 header and two three-u32 data
        // records. This reads only the calling thread's capability sets.
        let mut header = [0x2008_0522_u32, 0];
        let mut capabilities = [[0_u32; 3]; 2];
        // SAFETY: these initialized arrays match capget v3's native layout,
        // have the required lengths, and pid zero queries the calling thread.
        let capability_result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_capget,
                header.as_mut_ptr(),
                capabilities.as_mut_ptr(),
            )
        };
        if nix::unistd::getuid().is_root()
            || nix::unistd::geteuid().is_root()
            || capability_result != 0
            || capabilities.iter().flatten().any(|value| *value != 0)
        {
            eprintln!("unexercised: requires native non-root identity without capabilities");
            return;
        }

        const MARKER: &str = "DEV_AUTH_PLAN_IDENTITY_FAILURE_MARKER";
        if let Some(marker) = std::env::var_os(MARKER) {
            std::fs::write(marker, b"payload-executed").unwrap();
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("payload-executed");
        let fixture = concat!(
            module_path!(),
            "::selected_identity_syscall_failure_prevents_payload_exec"
        );
        let (_, fixture) = fixture.split_once("::").unwrap();
        let payload = || {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", fixture, "--nocapture"])
                .env(MARKER, &marker)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            command
        };

        // Positive control proves the finite native payload reaches its marker.
        let mut control = payload().spawn().unwrap();
        // One fixed five-second budget includes one second reserved for cleanup;
        // no timeout/error path replaces it with an unbounded terminal wait.
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = match observe_until(&mut control, deadline - Duration::from_secs(1)) {
            Ok(Some(status)) => status,
            outcome => {
                let cleanup = cleanup_until(&mut control, deadline);
                panic!("identity failure marker control did not finish: {outcome:?}; {cleanup}");
            }
        };
        assert!(status.success());
        assert_eq!(std::fs::read(&marker).unwrap(), b"payload-executed");
        std::fs::remove_file(&marker).unwrap();

        let identity = RunAsIdentity {
            uid: 0,
            gid: 0,
            supplementary_groups: vec![],
        };
        identity.validate().unwrap();
        let mut original: nix::libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: read-only query writes the initialized native mask buffer.
        assert_eq!(
            unsafe {
                nix::libc::pthread_sigmask(nix::libc::SIG_SETMASK, std::ptr::null(), &mut original)
            },
            0
        );
        let mut command = payload();
        // SAFETY: this invokes the exact production callback only in the forked
        // child, with validated owned groups and the captured original mask.
        unsafe {
            command.pre_exec(move || apply_child_identity_and_mask(Some(&identity), &original));
        }
        match command.spawn() {
            Err(error) => assert_eq!(error.raw_os_error(), Some(nix::libc::EPERM)),
            Ok(mut child) => {
                let cleanup = cleanup_until(&mut child, Instant::now() + Duration::from_secs(1));
                panic!("selected identity failure unexpectedly reached payload exec; {cleanup}");
            }
        }
        assert!(
            !marker.exists(),
            "failed identity must not execute the payload"
        );
    }

    #[test]
    fn worker_plan_is_sealed_and_read_once_without_a_named_file() {
        let plan = ExecutionPlan {
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
            exit_policy: ExitPolicy::All,
            output_limit_bytes: None,
        };
        let prepared = prepare(
            plan.clone(),
            dev_tools_privilege_session::linux::boot_time().unwrap() + Duration::from_secs(3),
            false,
        )
        .unwrap();
        assert!(prepared.null_device.is_none());
        assert!(matches!(
            selected_stream(Some(PlanStreamMode::Null), None),
            Err(Failure::InvalidRequest)
        ));
        assert!(matches!(
            take_null_device(
                Some(&NullDevice {
                    descriptor: 2,
                    device: 0,
                    inode: 0,
                }),
                prepared.snapshot.as_raw_fd()
            ),
            Err(Failure::InvalidRequest)
        ));
        let fd = prepared.snapshot;
        assert!(rustix::fs::fcntl_get_seals(fd.as_fd())
            .unwrap()
            .contains(required_seals()));
        let mut original: nix::libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: read-only query writes the initialized local native mask.
        assert_eq!(
            unsafe {
                nix::libc::pthread_sigmask(nix::libc::SIG_SETMASK, std::ptr::null(), &mut original)
            },
            0
        );
        assert!(read_and_run(fd.into(), original).unwrap().success());

        let mut null_plan = plan;
        null_plan.nodes[0].stdout = Some(PlanStreamMode::Null);
        let prepared = prepare(
            null_plan,
            dev_tools_privilege_session::linux::boot_time().unwrap() + Duration::from_secs(3),
            false,
        )
        .unwrap();
        let null_device = prepared.null_device.unwrap();
        assert!(rustix::io::fcntl_getfd(&null_device)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        let metadata = File::from(null_device.try_clone().unwrap())
            .metadata()
            .unwrap();
        assert!(is_native_null(&metadata));
        let mut snapshot = File::from(prepared.snapshot);
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes).unwrap();
        let snapshot: Snapshot = serde_json::from_slice(&bytes).unwrap();
        let identity = snapshot.null_device.unwrap();
        assert_eq!(identity.descriptor, null_device.as_raw_fd());
        assert_eq!(identity.device, metadata.dev());
        assert_eq!(identity.inode, metadata.ino());
        assert!(!snapshot.terminal);
    }

    #[test]
    fn named_graph_selection_cannot_expand_the_grant() {
        let plan = ExecutionPlan {
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
            exit_policy: ExitPolicy::All,
            output_limit_bytes: None,
        };
        let mut policy = Policy::template();
        policy.operations.insert("allowed".into(), plan.clone());
        policy.operations.insert("other".into(), plan);
        let grant = Authority::Typed {
            operations: vec!["allowed".into()],
        };
        assert!(select(&policy, &grant, &grant).is_ok());
        assert!(select(
            &policy,
            &grant,
            &Authority::Typed {
                operations: vec!["other".into()]
            }
        )
        .is_err());
        assert!(select(
            &policy,
            &Authority::Administrator,
            &Authority::Typed {
                operations: vec!["missing".into()]
            }
        )
        .is_err());
    }
}
