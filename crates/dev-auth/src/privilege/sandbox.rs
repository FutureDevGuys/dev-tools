//! An operation-only namespace boundary. This is not a general root shell.
//!
//! The receipt-owned single-threaded helper enters this code only after the
//! coordinator's native cgroup gate. A trusted PID-1 init reaps the actual helper
//! and its descendants. Only the helper (PID 2 or later) executes payload bytes.
//! Descriptor-relative private mounts expose public runtime and approved scope.
//!
//! Pipe core collectors are suppressed by exact soft/hard RLIMIT_CORE=1,
//! established before forks/exec and frozen by inherited syscall rules. File
//! paths remain inside the private filesystem. Socket (@/@@) collectors have
//! no equivalent guard and are rejected by the retained platform profile.
//! Trusted root infrastructure also starts with limit1 and DUMPABLE0; ordinary
//! exec resets dumpability, so payload safety never relies on pre-exec prctl.
//! No host core settings change. Native collector-negative qualification is
//! mandatory before release/deployment support is claimed.
//! See https://github.com/torvalds/linux/blob/v6.17/fs/coredump.c.
use super::{
    custody::HeldResource,
    policy::{Access, ExactPlan},
};
use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

const PUBLIC_RUNTIME: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
];
const DEVICES: &[(&str, u32)] = &[
    ("/dev/null", 3),
    ("/dev/zero", 5),
    ("/dev/random", 8),
    ("/dev/urandom", 9),
];
const FILESYSTEM_CAPABILITIES: u64 = 0x1b;
// Lock NOROOT, NO_SETUID_FIXUP, KEEP_CAPS (off), and NO_CAP_AMBIENT_RAISE (on).
// The ambient set is populated before this lock and cannot be widened afterward.
const LOCKED_SECUREBITS: i32 = 0xef;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const AT_RECURSIVE: u32 = 0x8000;
const MOVE_MOUNT_EMPTY_PATHS: u32 = 0x4 | 0x40;

/// Called in a fresh private product helper, before it creates any threads.
/// The caller already owns cgroup and native expiry/cleanup enforcement.
pub fn execute(
    plan: &ExactPlan,
    root: &Path,
    descriptors: Vec<super::custody::ResourceDescriptor>,
) -> Result<i32> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getuid() != nix::unistd::geteuid() {
        bail!("administrative sandbox requires native root infrastructure");
    }
    super::platform::protect_infrastructure()?;
    if descriptors.len() != plan.resources.len() {
        bail!("administrative resource transfer is incomplete");
    }
    let mut names = std::collections::BTreeSet::new();
    let resources = descriptors
        .iter()
        .map(|d| {
            if !names.insert(&d.name) {
                bail!("administrative resource transfer is ambiguous");
            }
            let declared = plan
                .resources
                .get(&d.name)
                .context("administrative resource is outside plan")?;
            if Path::new(&declared.path) != d.path {
                bail!("administrative resource transfer changed scope");
            }
            Ok((HeldResource::inherited(d)?, declared.access))
        })
        .collect::<Result<Vec<_>>>()?;
    let executable =
        super::custody::held_root_executable(Path::new(&plan.executable), &plan.executable_sha256)?;
    let input = input_file(&plan.input)?;
    let (status_read, status_write) = private_pipe()?;
    restore_child_wait_semantics()?;
    super::platform::CoreDumpProfile::capture()?;
    let flags = nix::libc::CLONE_NEWNS
        | nix::libc::CLONE_NEWPID
        | nix::libc::CLONE_NEWIPC
        | nix::libc::CLONE_NEWUTS
        | nix::libc::CLONE_NEWNET;
    // SAFETY: this is a dedicated single-threaded helper. All process owners
    // stay in the retained operation cgroup and under its independent deadline.
    if unsafe { nix::libc::unshare(flags) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("create administrative operation namespaces");
    }
    // SAFETY: the dedicated helper has no other threads or shared Rust state.
    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { child } => {
            drop(status_write);
            drop((resources, executable, input));
            let init_status = wait_one(child.as_raw())?;
            let status = if init_status == NativeStatus::Exit(0) {
                let mut file = File::from(status_read);
                let mut frame = [0u8; 8];
                file.read_exact(&mut frame)
                    .context("read namespace terminal status")?;
                let mut trailing = [0u8; 1];
                if file.read(&mut trailing)? != 0 {
                    bail!("namespace terminal status has trailing data");
                }
                NativeStatus::decode(frame)?
            } else {
                // An independently killed init has no successful payload report.
                // Preserve that native signal rather than manufacturing an exit.
                init_status
            };
            match status {
                NativeStatus::Exit(code) => Ok(code),
                NativeStatus::Signal(signal) => reraise_signal(signal),
            }
        }
        nix::unistd::ForkResult::Child => {
            drop(status_read);
            namespace_init(plan, root, resources, executable, input, status_write)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStatus {
    Exit(i32),
    Signal(i32),
}

impl NativeStatus {
    fn from_wait(status: i32) -> Result<Self> {
        if nix::libc::WIFEXITED(status) {
            Ok(Self::Exit(nix::libc::WEXITSTATUS(status)))
        } else if nix::libc::WIFSIGNALED(status) {
            Ok(Self::Signal(nix::libc::WTERMSIG(status)))
        } else {
            bail!("administrative child did not terminate")
        }
    }

    fn encode(self) -> [u8; 8] {
        let (kind, code) = match self {
            Self::Exit(code) => (0, code),
            Self::Signal(code) => (1, code),
        };
        let mut bytes = [0x50, 0x53, 1, kind, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&code.to_le_bytes());
        bytes
    }

    fn decode(bytes: [u8; 8]) -> Result<Self> {
        if bytes[..3] != [0x50, 0x53, 1] {
            bail!("namespace terminal status is invalid");
        }
        let code = i32::from_le_bytes(bytes[4..].try_into()?);
        match (bytes[3], code) {
            (0, 0..=255) => Ok(Self::Exit(code)),
            (1, 1..=64) => Ok(Self::Signal(code)),
            _ => bail!("namespace terminal status is invalid"),
        }
    }
}

fn restore_child_wait_semantics() -> Result<()> {
    // A launcher may have ignored SIGCHLD or set SA_NOCLDWAIT. Reset both
    // before the outer fork, so neither init nor payload status is discarded.
    let mut action: nix::libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = nix::libc::SIG_DFL;
    if unsafe { nix::libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { nix::libc::sigaction(nix::libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("restore administrative child wait semantics");
    }
    Ok(())
}

fn wait_one(pid: i32) -> Result<NativeStatus> {
    loop {
        let mut status = 0;
        // SAFETY: waitpid writes one initialized native status word.
        let result = unsafe { nix::libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return NativeStatus::from_wait(status);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(nix::libc::EINTR) {
            return Err(error).context("join administrative namespace init");
        }
    }
}

fn reap_namespace(helper: i32) -> Result<NativeStatus> {
    let mut helper_status = None;
    loop {
        let mut status = 0;
        // SAFETY: PID 1 owns every child/adopted orphan in this private namespace.
        let pid = unsafe { nix::libc::waitpid(-1, &mut status, 0) };
        if pid > 0 {
            let status = NativeStatus::from_wait(status)?;
            if record_namespace_exit(helper, &mut helper_status, pid, status) {
                terminate_namespace_descendants()?;
            }
            continue;
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(nix::libc::EINTR) => continue,
            Some(nix::libc::ECHILD) => break,
            _ => return Err(error).context("reap administrative namespace descendants"),
        }
    }
    helper_status.context("administrative helper terminal status is absent")
}

fn record_namespace_exit(
    helper: i32,
    helper_status: &mut Option<NativeStatus>,
    reaped: i32,
    status: NativeStatus,
) -> bool {
    if reaped == helper {
        *helper_status = Some(status);
    }
    // Every reap after the actual transaction leader ends requests immediate
    // descendant cleanup; descendant signals must never replace its status.
    helper_status.is_some()
}

fn terminate_namespace_descendants() -> Result<()> {
    if nix::unistd::getpid().as_raw() != 1 {
        bail!("administrative descendant cleanup requires the private init");
    }
    // Linux kill(-1) excludes PID 1 and processes not visible in this PID
    // namespace. Payloads cannot change UID or create another user namespace,
    // so the zero-capability UID-0 init can signal all its UID-0 descendants.
    // Repeat after every reap to cover late forks. Independent cgroup kill and
    // population/join evidence remain mandatory even after this local cleanup.
    if unsafe { nix::libc::kill(-1, nix::libc::SIGKILL) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::ESRCH)
    {
        return Err(std::io::Error::last_os_error())
            .context("terminate administrative namespace descendants");
    }
    Ok(())
}

fn reraise_signal(signal: i32) -> ! {
    // This runs in the outer ordinary process, never PID 1. Reset any inherited
    // disposition and unblock the exact signal so native wait status is preserved.
    // SIGKILL's disposition cannot be changed, but it is already unconditionally fatal.
    // Suppress the privileged outer wrapper's core before re-raising: it still
    // has the host root, and a core_pattern pipe executes outside our namespaces.
    unsafe {
        if nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            nix::libc::_exit(126);
        }
        if signal != nix::libc::SIGKILL
            && nix::libc::signal(signal, nix::libc::SIG_DFL) == nix::libc::SIG_ERR
        {
            nix::libc::_exit(126);
        }
        let mut signals: nix::libc::sigset_t = std::mem::zeroed();
        if nix::libc::sigemptyset(&mut signals) != 0
            || nix::libc::sigaddset(&mut signals, signal) != 0
            || nix::libc::sigprocmask(nix::libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0
            || nix::libc::kill(nix::libc::getpid(), signal) != 0
        {
            nix::libc::_exit(126);
        }
        // No signal that produces WIFSIGNALED has a successful-return fallback.
        nix::libc::_exit(126)
    }
}

fn namespace_init(
    plan: &ExactPlan,
    root: &Path,
    resources: Vec<(HeldResource, Access)>,
    executable: dev_tools_command::HeldExecutable,
    input: File,
    status_write: OwnedFd,
) -> ! {
    let status_fd = status_write.as_raw_fd();
    let result = (|| -> Result<NativeStatus> {
        if nix::unistd::getpid().as_raw() != 1 {
            bail!("administrative init is outside its private PID namespace");
        }
        prepare_root(plan, root, resources, executable)?;
        let executable = super::custody::held_root_executable(
            Path::new(&plan.executable),
            &plan.executable_sha256,
        )?;
        // Payload access through /proc/1/{fd,root,mem} must not expose the trusted
        // reaper. No CAP_SYS_PTRACE survives in the payload.
        if unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error()).context("protect administrative init");
        }
        let (ready_read, ready_write) = private_pipe()?;
        // SAFETY: PID 1 is still a dedicated single-threaded trusted helper.
        match unsafe { nix::unistd::fork() }? {
            nix::unistd::ForkResult::Parent { child } => {
                drop(ready_read);
                drop((executable, input));
                // Init needs no capability or host descriptor to wait and reap.
                // Release PID2 only once the retained parent has been sealed.
                restrict_privilege(0)?;
                restrict_syscalls()?;
                File::from(ready_write).write_all(&[1])?;
                reap_namespace(child.as_raw())
            }
            nix::unistd::ForkResult::Child => {
                drop(ready_write);
                // SAFETY: close only the fork child's inherited status writer.
                // This branch always execs or _exits; it never drops the init's
                // Rust owner after that integer descriptor could be reused.
                unsafe {
                    nix::libc::close(status_fd);
                }
                let result = (|| -> Result<()> {
                    let mut ready = [0u8; 1];
                    File::from(ready_read).read_exact(&mut ready)?;
                    if ready != [1] || nix::unistd::getpid().as_raw() <= 1 {
                        bail!("administrative init release is invalid");
                    }
                    restrict_privilege(FILESYSTEM_CAPABILITIES)?;
                    restrict_syscalls()?;
                    let mut command =
                        executable.command(Path::new(&plan.executable).as_os_str())?;
                    command
                        .env_clear()
                        .args(plan.arguments.iter().cloned().map(OsString::from_vec))
                        .envs(&plan.environment)
                        .stdin(Stdio::from(input));
                    let executable_fd = executable.as_fd().as_raw_fd();
                    // This path accepts native ELF only. Shared HeldCommand's
                    // script support must not leave an executable descriptor open.
                    // The reopened descriptor already refers to the private RO mount.
                    unsafe {
                        command.pre_exec(move || {
                            if nix::libc::fcntl(
                                executable_fd,
                                nix::libc::F_SETFD,
                                nix::libc::FD_CLOEXEC,
                            ) != 0
                            {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(())
                        });
                    }
                    Err(command.exec()).context("execute approved administrative helper")
                })();
                // SAFETY: the fork child must not unwind into the init owner.
                unsafe { nix::libc::_exit(if result.is_ok() { 0 } else { 126 }) }
            }
        }
    })();
    let status = result.unwrap_or(NativeStatus::Exit(126));
    let written = File::from(status_write).write_all(&status.encode()).is_ok();
    // Exiting init tears down its namespace if setup failed before all children
    // could be reaped. Native cgroup cleanup remains a separate required proof.
    unsafe { nix::libc::_exit(if written { 0 } else { 126 }) }
}

struct BindSource {
    path: PathBuf,
    source: OwnedFd,
    directory: bool,
    read_only: bool,
    device_exception: bool,
}

fn prepare_root(
    plan: &ExactPlan,
    root: &Path,
    resources: Vec<(HeldResource, Access)>,
    executable: dev_tools_command::HeldExecutable,
) -> Result<()> {
    mount(
        None,
        Path::new("/"),
        None,
        nix::libc::MS_REC | nix::libc::MS_PRIVATE,
        None,
    )?;
    super::custody::validate_parents(root, 0, false)?;
    let root_target = rustix::fs::openat2(
        rustix::fs::CWD,
        root,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS,
    )?;
    let metadata = rustix::fs::fstat(&root_target)?;
    if metadata.st_uid != 0 || metadata.st_mode & 0o7777 != 0o700 {
        bail!("administrative private root has unsafe custody");
    }
    let private_root = filesystem_mount(
        "tmpfs",
        &[("mode", "0700"), ("size", "32m")],
        MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    )?;
    attach_mount(&private_root, &root_target)?;
    drop(root_target);
    let mut sources = Vec::new();
    for source in PUBLIC_RUNTIME {
        let source = Path::new(source);
        if !source.try_exists()? {
            continue;
        }
        let resolved = fs::canonicalize(source)?;
        super::custody::validate_parents(&resolved, 0, false)?;
        let fd = rustix::fs::open(
            &resolved,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let stat = rustix::fs::fstat(&fd)?;
        let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        if stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
            || !matches!(
                kind,
                rustix::fs::FileType::Directory | rustix::fs::FileType::RegularFile
            )
        {
            bail!("administrative runtime source has unsafe custody");
        }
        sources.push(BindSource {
            path: source.into(),
            source: fd,
            directory: kind == rustix::fs::FileType::Directory,
            read_only: true,
            device_exception: false,
        });
    }
    for (source, minor) in DEVICES {
        let path = Path::new(source);
        super::custody::validate_parents(path, 0, false)?;
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let stat = rustix::fs::fstat(&fd)?;
        if stat.st_uid != 0
            || rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::CharacterDevice
            || nix::libc::major(stat.st_rdev) != 1
            || nix::libc::minor(stat.st_rdev) != *minor
        {
            bail!("administrative device source is not an approved safe device");
        }
        sources.push(BindSource {
            path: path.into(),
            source: fd,
            directory: false,
            // Read-only prevents chmod/chown on the host device inode; it does
            // not prohibit normal character-device reads and writes.
            read_only: true,
            device_exception: true,
        });
    }
    for (resource, access) in &resources {
        resource.verify()?;
        sources.push(BindSource {
            path: resource.path.clone(),
            source: rustix::io::fcntl_dupfd_cloexec(&resource.descriptor, 3)?,
            directory: resource.is_directory()?,
            read_only: *access == Access::ReadOnly,
            device_exception: false,
        });
    }
    sources.push(BindSource {
        path: PathBuf::from(&plan.executable),
        source: rustix::io::fcntl_dupfd_cloexec(executable.as_fd(), 3)?,
        directory: false,
        read_only: true,
        device_exception: false,
    });
    // No filesystem target is created after the first bind. In particular, a
    // target below a writable resource can never cause mkdir/open on host data.
    for source in &sources {
        create_target(&private_root, &source.path, source.directory)?;
    }
    create_target(&private_root, Path::new("/proc"), true)?;
    for source in &sources {
        // Reopen the live target after earlier mounts, rather than mounting on
        // a pre-bind tmpfs inode now hidden beneath /usr or another ancestor.
        // IN_ROOT and NO_SYMLINKS reject any redirected or racing target path.
        let target = open_target(&private_root, &source.path, source.directory)?;
        bind(source, &target)?;
    }
    for (resource, _) in &resources {
        resource.verify()?;
    }
    let proc_mount = filesystem_mount(
        "proc",
        &[],
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
    )?;
    let proc_target = open_target(&private_root, Path::new("/proc"), true)?;
    attach_mount(&proc_mount, &proc_target)?;
    drop((proc_mount, proc_target, sources, resources, executable));
    // Enter the held private mount itself, never a freshly resolved host path.
    // SAFETY: the borrowed root descriptor remains live through both syscalls.
    if unsafe { nix::libc::fchdir(private_root.as_raw_fd()) } != 0
        || unsafe { nix::libc::chroot(c".".as_ptr()) } != 0
    {
        return Err(std::io::Error::last_os_error()).context("enter administrative resource root");
    }
    std::env::set_current_dir("/")?;
    drop(private_root);
    std::env::set_current_dir(&plan.working_directory)?;
    Ok(())
}

fn target_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>> {
    let components: Vec<_> = path.components().collect();
    let normalized: PathBuf = components.iter().collect();
    if !path.is_absolute()
        || normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes()
        || components.len() < 2
        || components.len() > 64
        || !matches!(components.first(), Some(Component::RootDir))
        || components[1..]
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("sandbox target must be an exact absolute descendant");
    }
    Ok(components
        .into_iter()
        .skip(1)
        .map(|part| part.as_os_str())
        .collect())
}

fn open_target(root: &OwnedFd, path: &Path, directory: bool) -> Result<OwnedFd> {
    target_components(path)?;
    let fd = rustix::fs::openat2(
        root,
        path,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::CLOEXEC
            | if directory {
                rustix::fs::OFlags::DIRECTORY
            } else {
                rustix::fs::OFlags::empty()
            },
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::IN_ROOT | rustix::fs::ResolveFlags::NO_SYMLINKS,
    )?;
    let kind = rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode);
    if directory && kind != rustix::fs::FileType::Directory
        || !directory && kind != rustix::fs::FileType::RegularFile
    {
        bail!("sandbox target has the wrong native type");
    }
    Ok(fd)
}

fn create_target(root: &OwnedFd, path: &Path, directory: bool) -> Result<()> {
    let components = target_components(path)?;
    let mut current = rustix::io::fcntl_dupfd_cloexec(root, 3)?;
    let mut relative = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        relative.push(component);
        let is_directory = index + 1 != components.len() || directory;
        if is_directory {
            match rustix::fs::mkdirat(&current, *component, rustix::fs::Mode::from_raw_mode(0o700))
            {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            match rustix::fs::openat2(
                root,
                &relative,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
                rustix::fs::ResolveFlags::IN_ROOT | rustix::fs::ResolveFlags::NO_SYMLINKS,
            ) {
                Ok(fd) => drop(fd),
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        current = open_target(root, &Path::new("/").join(&relative), is_directory)?;
    }
    Ok(())
}

fn filesystem_mount(
    filesystem: &str,
    options: &[(&str, &str)],
    attributes: u64,
) -> Result<OwnedFd> {
    let filesystem = CString::new(filesystem)?;
    // SAFETY: fsopen reads the fixed live filesystem name and returns a new fd.
    let context = syscall_fd(unsafe {
        nix::libc::syscall(nix::libc::SYS_fsopen, filesystem.as_ptr(), 1u32)
    })?;
    for (key, value) in options {
        let key = CString::new(*key)?;
        let value = CString::new(*value)?;
        // FSCONFIG_SET_STRING: initialized NUL-terminated key and value.
        if unsafe {
            nix::libc::syscall(
                nix::libc::SYS_fsconfig,
                context.as_raw_fd(),
                1u32,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("configure administrative private filesystem");
        }
    }
    // FSCONFIG_CMD_CREATE has no key/value pointers.
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_fsconfig,
            context.as_raw_fd(),
            6u32,
            std::ptr::null::<nix::libc::c_char>(),
            std::ptr::null::<nix::libc::c_char>(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("create administrative private filesystem");
    }
    // FSMOUNT_CLOEXEC creates a retained detached mount with its final flags.
    syscall_fd(unsafe {
        nix::libc::syscall(
            nix::libc::SYS_fsmount,
            context.as_raw_fd(),
            1u32,
            u32::try_from(attributes)?,
        )
    })
}

fn syscall_fd(result: nix::libc::c_long) -> Result<OwnedFd> {
    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("retain administrative mount authority");
    }
    // SAFETY: these descriptor-producing syscalls transfer a new owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(i32::try_from(result)?) })
}

fn attach_mount(mount: &OwnedFd, target: &OwnedFd) -> Result<()> {
    // Both source and destination are held mount/dentry handles. No target path
    // is followed by move_mount, and an unlinked target fails closed.
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_move_mount,
            mount.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            MOVE_MOUNT_EMPTY_PATHS,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("attach retained administrative mount");
    }
    Ok(())
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

fn bind(source: &BindSource, target: &OwnedFd) -> Result<()> {
    // OPEN_TREE_CLONE|CLOEXEC creates a private bind tree from the held source.
    // Only read-only directory sources deliberately import nested mounts.
    // Writable resources retain the approved nonrecursive source boundary.
    let clone_flags = bind_clone_flags(source.directory, source.read_only);
    let attribute_flags = bind_attribute_flags(source.directory);
    let tree = syscall_fd(unsafe {
        nix::libc::syscall(
            nix::libc::SYS_open_tree,
            source.source.as_raw_fd(),
            c"".as_ptr(),
            clone_flags,
        )
    })?;
    let attributes = bind_attributes(source.read_only, source.device_exception);
    // Seal every mount actually admitted into the detached clone. Attribute
    // recursion does not broaden source-clone recursion. No weaker remount
    // fallback is allowed on kernels lacking recursive mount_setattr support.
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            attribute_flags,
            &attributes,
            std::mem::size_of::<MountAttr>(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("seal administrative bind mount");
    }
    attach_mount(&tree, target)
}

fn bind_clone_flags(directory: bool, read_only: bool) -> u32 {
    1u32 | nix::libc::O_CLOEXEC as u32
        | nix::libc::AT_EMPTY_PATH as u32
        | if directory && read_only {
            AT_RECURSIVE
        } else {
            0
        }
}

fn bind_attribute_flags(directory: bool) -> u32 {
    nix::libc::AT_EMPTY_PATH as u32 | if directory { AT_RECURSIVE } else { 0 }
}

fn bind_attributes(read_only: bool, device_exception: bool) -> MountAttr {
    MountAttr {
        attr_set: MOUNT_ATTR_NOSUID
            | if device_exception {
                MOUNT_ATTR_NOEXEC
            } else {
                MOUNT_ATTR_NODEV
            }
            | if read_only { MOUNT_ATTR_RDONLY } else { 0 },
        attr_clr: if device_exception {
            MOUNT_ATTR_NODEV
        } else {
            0
        },
        propagation: 0,
        userns_fd: 0,
    }
}

fn mount(
    source: Option<&str>,
    target: &Path,
    filesystem: Option<&str>,
    flags: nix::libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let source = source.map(CString::new).transpose()?;
    let filesystem = filesystem.map(CString::new).transpose()?;
    let data = data.map(CString::new).transpose()?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: every non-null pointer names a live NUL-terminated byte buffer.
    if unsafe {
        nix::libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            filesystem.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("prepare administrative mount boundary");
    }
    Ok(())
}

fn private_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe2 initializes two newly owned descriptors on success.
    if unsafe { nix::libc::pipe2(descriptors.as_mut_ptr(), nix::libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("create private init control pipe");
    }
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    // Standard-stream setup must not overwrite any retained control operand.
    Ok((
        rustix::io::fcntl_dupfd_cloexec(&read, 3)?,
        rustix::io::fcntl_dupfd_cloexec(&write, 3)?,
    ))
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

fn capset(effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
    let header = CapabilityHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        CapabilityData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];
    // SAFETY: capset reads exactly two initialized v3 capability words.
    if unsafe { nix::libc::syscall(nix::libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("restrict administrative capabilities");
    }
    Ok(())
}

fn restrict_privilege(allowed: u64) -> Result<()> {
    if allowed != 0 && allowed != FILESYSTEM_CAPABILITIES {
        bail!("administrative capability audience is invalid");
    }
    // Clear any inherited ambient authority before preparing our exact set.
    if unsafe {
        nix::libc::prctl(
            nix::libc::PR_CAP_AMBIENT,
            nix::libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("clear inherited ambient privilege");
    }
    for capability in 0..64 {
        let present = unsafe { nix::libc::prctl(nix::libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        if present < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EINVAL)
                && allowed & (1u64 << capability) == 0
            {
                continue;
            }
            return Err(std::io::Error::last_os_error())
                .context("inspect administrative capability bound");
        }
        if allowed & (1u64 << capability) != 0 {
            if present != 1 {
                bail!("required filesystem capability is unavailable");
            }
        } else if unsafe { nix::libc::prctl(nix::libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("restrict administrative capability bounds");
        }
    }
    // Keep SETPCAP only while locking securebits. It is never inheritable,
    // ambient or in the final bounding/permitted/effective payload sets.
    let setup = allowed | (1u64 << 8);
    capset(setup, setup, allowed)?;
    for capability in 0..64 {
        if allowed & (1u64 << capability) != 0
            && unsafe {
                nix::libc::prctl(
                    nix::libc::PR_CAP_AMBIENT,
                    nix::libc::PR_CAP_AMBIENT_RAISE,
                    capability,
                    0,
                    0,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("preserve explicit filesystem privilege across exec");
        }
    }
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_SECUREBITS, LOCKED_SECUREBITS, 0, 0, 0) } != 0
        || unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("lock administrative execution privilege");
    }
    capset(allowed, allowed, allowed)?;
    verify_privilege(allowed)
}

fn verify_privilege(allowed: u64) -> Result<()> {
    let header = CapabilityHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [CapabilityData::default(); 2];
    if unsafe { nix::libc::syscall(nix::libc::SYS_capget, &header, data.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("verify administrative capabilities");
    }
    let effective = data[0].effective as u64 | ((data[1].effective as u64) << 32);
    let permitted = data[0].permitted as u64 | ((data[1].permitted as u64) << 32);
    let inheritable = data[0].inheritable as u64 | ((data[1].inheritable as u64) << 32);
    if effective != allowed
        || permitted != allowed
        || inheritable != allowed
        || unsafe { nix::libc::prctl(nix::libc::PR_GET_SECUREBITS, 0, 0, 0, 0) }
            != LOCKED_SECUREBITS
        || unsafe { nix::libc::prctl(nix::libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
    {
        bail!("administrative capability lock is incomplete");
    }
    for capability in 0..64 {
        let bound = unsafe { nix::libc::prctl(nix::libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        let ambient = unsafe {
            nix::libc::prctl(
                nix::libc::PR_CAP_AMBIENT,
                nix::libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        let expected = i32::from(allowed & (1u64 << capability) != 0);
        if bound < 0
            && ambient < 0
            && expected == 0
            && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EINVAL)
        {
            continue;
        }
        if bound != expected || ambient != expected {
            bail!("administrative ambient or bounding capability set changed");
        }
    }
    Ok(())
}

fn input_file(bytes: &[u8]) -> Result<std::fs::File> {
    let name = CString::new("dev-auth-operation-input")?;
    // SAFETY: a fixed NUL-terminated name; the returned fd is adopted once.
    let fd = unsafe {
        nix::libc::memfd_create(
            name.as_ptr(),
            nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create bounded input");
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let seals = nix::libc::F_SEAL_SEAL
        | nix::libc::F_SEAL_SHRINK
        | nix::libc::F_SEAL_GROW
        | nix::libc::F_SEAL_WRITE;
    if unsafe { nix::libc::fcntl(fd, nix::libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error()).context("seal bounded input");
    }
    Ok(file)
}

// No inherited external socket or directory authority reaches the ELF payload.
// Block alternate namespace/network/kernel entry points, including io_uring,
// which would otherwise permit operations outside a syscall-level socket gate.
fn syscall_filter() -> Result<Vec<nix::libc::sock_filter>> {
    const LD_ABS: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const JGE: u16 = 0x35;
    const RET: u16 = 0x06;
    const AND: u16 = 0x54;
    const KILL: u32 = 0x8000_0000;
    const ALLOW: u32 = 0x7fff_0000;
    const ERRNO: u32 = 0x0005_0000;
    let arch = if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else if cfg!(target_arch = "aarch64") {
        0xc000_00b7
    } else {
        bail!("administrative syscall architecture is unsupported");
    };
    let statement = |code, k| nix::libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code, k, jt, jf| nix::libc::sock_filter { code, jt, jf, k };
    let mut filter = vec![
        statement(LD_ABS, 4),
        jump(JEQ, arch, 1, 0),
        statement(RET, KILL),
        statement(LD_ABS, 0),
        jump(JGE, 0x4000_0000, 0, 1),
        statement(RET, KILL),
    ];
    for syscall in [
        nix::libc::SYS_socket,
        nix::libc::SYS_connect,
        nix::libc::SYS_setns,
        nix::libc::SYS_unshare,
        nix::libc::SYS_mount,
        nix::libc::SYS_fsopen,
        nix::libc::SYS_fsconfig,
        nix::libc::SYS_fsmount,
        nix::libc::SYS_open_tree,
        nix::libc::SYS_move_mount,
        nix::libc::SYS_mount_setattr,
        nix::libc::SYS_umount2,
        nix::libc::SYS_pivot_root,
        nix::libc::SYS_ptrace,
        nix::libc::SYS_process_vm_writev,
        nix::libc::SYS_bpf,
        nix::libc::SYS_open_by_handle_at,
        nix::libc::SYS_io_uring_setup,
        nix::libc::SYS_io_uring_enter,
        nix::libc::SYS_io_uring_register,
    ] {
        filter.push(jump(JEQ, syscall as u32, 0, 1));
        filter.push(statement(RET, ERRNO | nix::libc::EPERM as u32));
    }
    // Native syscalls truncate resource numbers to u32. Checking the high
    // half would admit CORE|(1<<32). A new_limit pointer is instead a full
    // native 64-bit value: both halves must be zero for a read-only query.
    // The architecture/x32 guards above execute before any argument rule.
    filter.extend([
        jump(JEQ, nix::libc::SYS_setrlimit as u32, 0, 4),
        statement(LD_ABS, 16),
        jump(JEQ, nix::libc::RLIMIT_CORE, 0, 1),
        statement(RET, ERRNO | nix::libc::EPERM as u32),
        statement(LD_ABS, 0),
        jump(JEQ, nix::libc::SYS_prlimit64 as u32, 0, 8),
        statement(LD_ABS, 24),
        jump(JEQ, nix::libc::RLIMIT_CORE, 0, 5),
        statement(LD_ABS, 32),
        jump(JEQ, 0, 0, 2),
        statement(LD_ABS, 36),
        jump(JEQ, 0, 1, 0),
        statement(RET, ERRNO | nix::libc::EPERM as u32),
        statement(LD_ABS, 0),
    ]);
    filter.push(jump(JEQ, nix::libc::SYS_clone3 as u32, 0, 1));
    filter.push(statement(RET, ERRNO | nix::libc::ENOSYS as u32));
    filter.push(jump(JEQ, nix::libc::SYS_clone as u32, 0, 4));
    filter.push(statement(LD_ABS, 16));
    filter.push(statement(
        AND,
        (nix::libc::CLONE_NEWNS
            | nix::libc::CLONE_NEWCGROUP
            | nix::libc::CLONE_NEWUTS
            | nix::libc::CLONE_NEWIPC
            | nix::libc::CLONE_NEWUSER
            | nix::libc::CLONE_NEWPID
            | nix::libc::CLONE_NEWNET) as u32,
    ));
    filter.push(jump(JEQ, 0, 1, 0));
    filter.push(statement(RET, ERRNO | nix::libc::EPERM as u32));
    filter.push(statement(RET, ALLOW));
    Ok(filter)
}

fn restrict_syscalls() -> Result<()> {
    let mut filter = syscall_filter()?;
    let program = nix::libc::sock_fprog {
        len: u16::try_from(filter.len())?,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: the kernel copies this initialized bounded BPF program before return.
    if unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_SECCOMP,
            nix::libc::SECCOMP_MODE_FILTER,
            &program,
            0,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("restrict administrative syscall authority");
    }
    Ok(())
}

/// Opt-in source fixture only: exercise the exact inherited process-local
/// filter without namespaces or privilege, in a disposable child process.
#[cfg(feature = "native-privilege-fixture")]
pub fn native_fixture_lock_core() -> Result<()> {
    super::platform::constrain_core_limit()?;
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("fixture no-new-privileges");
    }
    restrict_syscalls()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate_filter(nr: u32, arch: u32, arguments: [u64; 6]) -> u32 {
        let filter = syscall_filter().unwrap();
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(&nr.to_le_bytes());
        bytes[4..8].copy_from_slice(&arch.to_le_bytes());
        for (index, argument) in arguments.iter().enumerate() {
            bytes[16 + index * 8..24 + index * 8].copy_from_slice(&argument.to_le_bytes());
        }
        let mut pc = 0;
        let mut accumulator = 0;
        for _ in 0..filter.len() + 1 {
            let op = &filter[pc];
            pc += 1;
            match op.code {
                0x20 => {
                    accumulator = u32::from_le_bytes(
                        bytes[op.k as usize..op.k as usize + 4].try_into().unwrap(),
                    )
                }
                0x15 => pc += if accumulator == op.k { op.jt } else { op.jf } as usize,
                0x35 => pc += if accumulator >= op.k { op.jt } else { op.jf } as usize,
                0x54 => accumulator &= op.k,
                0x06 => return op.k,
                _ => panic!("unexpected filter instruction"),
            }
        }
        panic!("filter did not terminate")
    }
    #[test]
    fn inherited_core_filter_blocks_truncated_resources_and_full_width_write_pointers() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000_003e
        } else {
            0xc000_00b7
        };
        const ALLOW: u32 = 0x7fff_0000;
        let deny = 0x0005_0000 | nix::libc::EPERM as u32;
        for high in [0, 1u64 << 32, 0xffff_ffff_0000_0000] {
            let core = high | nix::libc::RLIMIT_CORE as u64;
            assert_eq!(
                evaluate_filter(nix::libc::SYS_setrlimit as u32, arch, [core, 0, 0, 0, 0, 0]),
                deny
            );
            for pid in [0, 1, u64::MAX] {
                for pointer in [1, 1 << 32, u64::MAX] {
                    assert_eq!(
                        evaluate_filter(
                            nix::libc::SYS_prlimit64 as u32,
                            arch,
                            [pid, core, pointer, 0, 0, 0]
                        ),
                        deny
                    );
                }
                assert_eq!(
                    evaluate_filter(
                        nix::libc::SYS_prlimit64 as u32,
                        arch,
                        [pid, core, 0, 1 << 32, 0, 0]
                    ),
                    ALLOW
                );
            }
        }
        for resource in [
            nix::libc::RLIMIT_NOFILE as u64,
            (1u64 << 32) | nix::libc::RLIMIT_STACK as u64,
        ] {
            assert_eq!(
                evaluate_filter(
                    nix::libc::SYS_setrlimit as u32,
                    arch,
                    [resource, 1, 0, 0, 0, 0]
                ),
                ALLOW
            );
            assert_eq!(
                evaluate_filter(
                    nix::libc::SYS_prlimit64 as u32,
                    arch,
                    [0, resource, 1, 0, 0, 0]
                ),
                ALLOW
            );
        }
        assert_eq!(
            evaluate_filter(nix::libc::SYS_prlimit64 as u32 | 0x4000_0000, arch, [0; 6]),
            0x8000_0000
        );
        assert_eq!(
            evaluate_filter(nix::libc::SYS_setrlimit as u32, 0x4000_0003, [0; 6]),
            0x8000_0000
        );
    }

    #[test]
    fn signal_status_cannot_be_confused_with_a_numeric_exit() {
        for code in [0, 1, 126, 130, 139, 255] {
            let status = NativeStatus::Exit(code);
            assert_eq!(NativeStatus::decode(status.encode()).unwrap(), status);
            assert_eq!(NativeStatus::from_wait(code << 8).unwrap(), status);
        }
        for signal in [
            nix::libc::SIGTERM,
            nix::libc::SIGSEGV,
            nix::libc::SIGKILL,
            64,
        ] {
            let status = NativeStatus::Signal(signal);
            assert_eq!(NativeStatus::decode(status.encode()).unwrap(), status);
            assert_eq!(NativeStatus::from_wait(signal).unwrap(), status);
            assert_ne!(status.encode(), NativeStatus::Exit(128 + signal).encode());
        }
        assert!(NativeStatus::decode([0; 8]).is_err());
        assert!(NativeStatus::decode(NativeStatus::Signal(0).encode()).is_err());
        assert!(NativeStatus::decode(NativeStatus::Signal(65).encode()).is_err());
        assert!(NativeStatus::decode(NativeStatus::Exit(256).encode()).is_err());
    }

    #[test]
    fn leader_exit_immediately_requests_descendant_cleanup_without_losing_its_status() {
        for leader in [
            NativeStatus::Exit(7),
            NativeStatus::Signal(nix::libc::SIGTERM),
        ] {
            let mut retained = None;
            assert!(!record_namespace_exit(
                2,
                &mut retained,
                3,
                NativeStatus::Exit(0)
            ));
            assert!(record_namespace_exit(2, &mut retained, 2, leader));
            assert!(record_namespace_exit(
                2,
                &mut retained,
                4,
                NativeStatus::Signal(nix::libc::SIGKILL)
            ));
            assert_eq!(retained, Some(leader));
        }
    }

    #[test]
    fn writable_source_cloning_never_imports_nested_mounts() {
        let base = 1u32 | nix::libc::O_CLOEXEC as u32 | nix::libc::AT_EMPTY_PATH as u32;
        assert_eq!(bind_clone_flags(true, false), base);
        assert_eq!(bind_clone_flags(false, false), base);
        assert_eq!(bind_clone_flags(false, true), base);
        // Public runtime and admitted read-only directory sources retain their
        // deliberately recursive read-only view.
        assert_eq!(bind_clone_flags(true, true), base | AT_RECURSIVE);
        // Attribute sealing is independently recursive for an admitted
        // directory tree, including the nonrecursive writable clone.
        assert_eq!(
            bind_attribute_flags(true),
            nix::libc::AT_EMPTY_PATH as u32 | AT_RECURSIVE
        );
        assert_eq!(bind_attribute_flags(false), nix::libc::AT_EMPTY_PATH as u32);
    }

    #[test]
    fn all_resource_bind_attributes_are_nosuid_and_nodev_including_writable_resources() {
        for read_only in [false, true] {
            let attributes = bind_attributes(read_only, false);
            assert_eq!(attributes.attr_set & MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSUID);
            assert_eq!(attributes.attr_set & MOUNT_ATTR_NODEV, MOUNT_ATTR_NODEV);
            assert_eq!(attributes.attr_set & MOUNT_ATTR_RDONLY != 0, read_only);
            assert_eq!(attributes.attr_clr, 0);
        }
        let device = bind_attributes(true, true);
        assert_eq!(
            device.attr_set,
            MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC
        );
        assert_eq!(device.attr_clr, MOUNT_ATTR_NODEV);
        assert_eq!(
            DEVICES,
            [
                ("/dev/null", 3),
                ("/dev/zero", 5),
                ("/dev/random", 8),
                ("/dev/urandom", 9)
            ]
        );
    }

    #[test]
    fn filesystem_capabilities_and_securebit_locks_are_exact() {
        assert_eq!(
            FILESYSTEM_CAPABILITIES,
            (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4)
        );
        assert_eq!(LOCKED_SECUREBITS, 0xef);
        assert_eq!(LOCKED_SECUREBITS & (1 << 4), 0, "KEEP_CAPS must stay off");
        assert_eq!(LOCKED_SECUREBITS & 0xaa, 0xaa, "every securebit is locked");
    }

    #[test]
    fn mount_targets_are_exact_absolute_descendants() {
        assert!(target_components(Path::new("/usr/local/bin/helper")).is_ok());
        for path in ["/", "relative", "/a/../b", "/a/./b", "/a//b", "/a/"] {
            assert!(target_components(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn target_resolution_rejects_symlinks_without_touching_their_host_destination() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root_fd = rustix::fs::open(
            root.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        create_target(&root_fd, Path::new("/scope/sub/target"), false).unwrap();
        fs::remove_file(root.path().join("scope/sub/target")).unwrap();
        fs::remove_dir(root.path().join("scope/sub")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("scope/sub")).unwrap();
        assert!(open_target(&root_fd, Path::new("/scope/sub/target"), false).is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn target_reopen_observes_the_live_view_and_retained_target_identity_is_stable() {
        let root = tempfile::tempdir().unwrap();
        let root_fd = rustix::fs::open(
            root.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        create_target(&root_fd, Path::new("/runtime/helper"), false).unwrap();
        let old = open_target(&root_fd, Path::new("/runtime/helper"), false).unwrap();
        let original = rustix::fs::fstat(&old).unwrap();
        fs::rename(
            root.path().join("runtime"),
            root.path().join("hidden-pristine-runtime"),
        )
        .unwrap();
        fs::create_dir(root.path().join("runtime")).unwrap();
        fs::write(root.path().join("runtime/helper"), b"replacement view").unwrap();
        let live = open_target(&root_fd, Path::new("/runtime/helper"), false).unwrap();
        assert_ne!(rustix::fs::fstat(&live).unwrap().st_ino, original.st_ino);
        fs::remove_file(root.path().join("runtime/helper")).unwrap();
        std::os::unix::fs::symlink("/outside", root.path().join("runtime/helper")).unwrap();
        assert!(open_target(&root_fd, Path::new("/runtime/helper"), false).is_err());
        assert_eq!(rustix::fs::fstat(&old).unwrap().st_ino, original.st_ino);
    }
}
