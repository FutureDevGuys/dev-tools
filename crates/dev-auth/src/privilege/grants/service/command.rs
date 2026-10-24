//! Command-scoped grants (ADR 0139). One program, started as the caller in a
//! job boundary the coordinator owns, routes sudo through its own freshly
//! approved grant, and the grant ends when the program exits.

use super::*;
use crate::privilege::grants::approval::CommandDisclosure;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::FileExt;

/// Larger programs are refused rather than digested.
const MAX_PROGRAM_BYTES: u64 = 1 << 30;
/// `FUSE_SUPER_MAGIC` from Linux `magic.h`. A FUSE daemon chooses the
/// attributes and the bytes it serves, so neither identifies a program.
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

/// The account a program must be executable by: its uid, gid and groups.
pub(super) struct Runner {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

impl Runner {
    fn may_execute(&self, metadata: &std::fs::Metadata) -> bool {
        let bits = if metadata.uid() == self.uid {
            0o100
        } else if metadata.gid() == self.gid || self.groups.contains(&metadata.gid()) {
            0o010
        } else {
            0o001
        };
        metadata.mode() & bits != 0
    }
}

pub(super) struct Requested {
    pub request: GrantRequest,
    pub executable: OsString,
    pub execution: crate::privilege::grants::Execution,
}

/// The program a command grant runs: the descriptor the caller opened, the
/// canonical path verified to name it, and the digest of its bytes.
pub(super) struct Program {
    file: File,
    path: OsString,
    sha256: String,
    stamp: FileStamp,
    device: u64,
    inode: u64,
    owner: u32,
}

impl Program {
    /// Accept the caller's read-only descriptor only when it is a regular
    /// ELF file that the runner may execute from an executable, non-FUSE
    /// mount, and `path`, canonical and resolved inside `root` with no
    /// symlink, names that same file. Then digest the bytes it reads.
    pub(super) fn verify(
        root: &File,
        path: &OsStr,
        file: File,
        runner: &Runner,
    ) -> Result<Self, Failure> {
        let stamp = FileStamp::of(&file)?;
        let metadata = file.metadata().map_err(|_| Failure::AuthorityDenied)?;
        let access = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)
            .map_err(|_| Failure::InvalidRequest)?
            & nix::libc::O_ACCMODE;
        let mount = rustix::fs::fstatvfs(&file).map_err(|_| Failure::NativeUnavailable)?;
        let filesystem = rustix::fs::fstatfs(&file).map_err(|_| Failure::NativeUnavailable)?;
        let mut magic = [0_u8; 4];
        if !metadata.is_file()
            || access != nix::libc::O_RDONLY
            || !runner.may_execute(&metadata)
            || mount.f_flag.contains(rustix::fs::StatVfsMountFlags::NOEXEC)
            || filesystem.f_type as u64 == FUSE_SUPER_MAGIC
            || metadata.len() > MAX_PROGRAM_BYTES
            || file.read_at(&mut magic, 0).ok() != Some(magic.len())
            || &magic != b"\x7fELF"
        {
            return Err(Failure::InvalidRequest);
        }
        let relative = Path::new(path)
            .strip_prefix("/")
            .map_err(|_| Failure::InvalidRequest)?;
        let mut canonical = Vec::new();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(Failure::InvalidRequest);
            };
            canonical.push(b'/');
            canonical.extend_from_slice(name.as_encoded_bytes());
        }
        if canonical != path.as_encoded_bytes() {
            return Err(Failure::InvalidRequest);
        }
        let named = rustix::fs::openat2(
            root,
            relative,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::IN_ROOT
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| Failure::AuthorityDenied)?;
        if !native::same_file(&File::from(named), &file)? {
            return Err(Failure::AuthorityDenied);
        }
        let sha256 = digest(&file, metadata.len())?;
        if FileStamp::of(&file)? != stamp {
            return Err(Failure::AuthorityDenied);
        }
        Ok(Self {
            file,
            path: path.to_owned(),
            sha256,
            stamp,
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }

    /// Whether the descriptor still holds the bytes the approval named.
    pub(super) fn unchanged(&self) -> bool {
        FileStamp::look(&self.file) == Ok(self.stamp)
    }

    pub(super) fn disclosure<'a>(
        &'a self,
        execution: &'a crate::privilege::grants::Execution,
    ) -> CommandDisclosure<'a> {
        CommandDisclosure {
            path: &self.path,
            sha256: &self.sha256,
            device: self.device,
            inode: self.inode,
            owner: self.owner,
            argv0: &execution.program,
            arguments: &execution.arguments,
            working_directory: &execution.working_directory,
            environment: &execution.environment,
        }
    }
}

/// SHA-256 of exactly `length` bytes. A file that grows or shrinks while it
/// is read is refused.
fn digest(file: &File, length: u64) -> Result<String, Failure> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut offset = 0_u64;
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|_| Failure::NativeUnavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset += read as u64;
        if offset > length {
            return Err(Failure::AuthorityDenied);
        }
    }
    if offset != length {
        return Err(Failure::AuthorityDenied);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// The kernel identity of a cgroup directory, in the form a workload scope
/// key uses.
pub(super) fn cgroup_key(directory: &File) -> Result<u128, Failure> {
    let metadata = directory
        .metadata()
        .map_err(|_| Failure::NativeUnavailable)?;
    Ok((u128::from(metadata.dev()) << 64) | u128::from(metadata.ino()))
}

/// End every active command grant whose program a look finds exited. A look
/// that could not be taken changes nothing (ADR 0138).
pub(super) fn end_exited(state: &mut State, now: Duration) -> Result<(), Integrity> {
    let exited: Vec<_> = state
        .commands
        .iter()
        .filter(|(id, leader)| {
            routes(&state.registry, **id) && native::readable(leader) == Ok(true)
        })
        .map(|(id, _)| *id)
        .collect();
    for id in exited {
        state
            .registry
            .stop(id, StopReason::WorkloadEnded, now)
            .map_err(|_| Integrity::RecordsDisagree(id))?;
    }
    Ok(())
}

pub(super) async fn run(
    service: &Arc<Service>,
    caller: &Caller,
    requested: Requested,
    mut streams: Vec<OwnedFd>,
    connection: &OwnedFd,
    progress: &mut Progress,
) -> Result<ControlResult, Failure> {
    let Requested {
        mut request,
        executable,
        execution,
    } = requested;
    drop(setup_admission(service)?);
    if streams.len() != 5 {
        return Err(Failure::InvalidRequest);
    }
    let image = File::from(streams.pop().ok_or(Failure::InvalidRequest)?);
    // The program runs unconfined in the host namespaces, so a confined
    // caller would leave its confinement through it.
    if caller.confined()? {
        return Err(Failure::AuthorityDenied);
    }
    let Account::Unix { uid } = caller.scope.account else {
        return Err(Failure::AuthorityDenied);
    };
    let limits = service
        .policy
        .approve_limits(&caller.scope.account, &request)?;
    request.idle_seconds = effective_idle(&service.policy, &caller.scope.account, &request)?;
    caller.verify_directory(&execution.working_directory)?;
    if !crate::privilege::grants::approval::account_has_login(uid).await? {
        return Err(Failure::AuthorityDenied);
    }
    let umask = caller.umask()?;
    let groups = caller.groups()?;
    let runner = Runner {
        uid,
        gid: caller.peer.gid,
        groups: groups.clone(),
    };
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
            || !pending.insert(caller.scope.account.clone())
        {
            return Err(Failure::Busy);
        }
        PendingApproval {
            pending: &service.pending,
            account: caller.scope.account.clone(),
        }
    };
    let root = File::open(format!("/proc/{}/root", caller.peer.pid))
        .map_err(|_| Failure::AuthorityDenied)?;
    let program =
        tokio::task::spawn_blocking(move || Program::verify(&root, &executable, image, &runner))
            .await
            .map_err(|_| Failure::RuntimeFailure)??;
    if !caller.still_present() {
        return Err(Failure::AuthorityDenied);
    }
    let approval = crate::privilege::grants::approval::approve(
        caller,
        &request,
        &format!("{id:032x}"),
        connection,
        Some(&program.disclosure(&execution)),
    )
    .await;
    let mut state = service.state.lock().await;
    drop(pending);
    approval?;
    let setup_lease = setup_admission(service)?;
    if admission(state.phase, service.trust()).is_err()
        || !caller.still_present()
        || !program.unchanged()
    {
        return Err(Failure::AuthorityDenied);
    }
    if state.jobs.len() >= MAX_EXECUTIONS {
        return Err(Failure::Busy);
    }
    let (streams, events, master) =
        crate::privilege::grants::execution_io::prepare_streams(streams, execution.terminal)?;
    let now = now()?;
    let deadline = now
        .checked_add(limits.hard_timeout())
        .ok_or(Failure::InvalidRequest)?;
    let boundary =
        ExecutionBoundary::create(&service.parent, &format!("grant-{id:032x}"), deadline)
            .map_err(|_| Failure::NativeUnavailable)?;
    let job_id = new_id()?;
    let job_boundary = ExecutionBoundary::create(
        boundary.directory(),
        &format!("exec-{job_id:032x}"),
        deadline,
    )
    .map_err(|_| Failure::NativeUnavailable)?;
    let scope = NativeScope {
        account: caller.scope.account.clone(),
        workload: Some(cgroup_key(job_boundary.directory())?),
    };
    let permit = job_boundary
        .permit(vec![
            native::clone_fd(&service.coordinator)?,
            native::clone_fd(caller.peer.peer_pidfd())?,
            native::clone_fd(connection)?,
            boundary.gate().map_err(|_| Failure::RuntimeFailure)?,
        ])
        .map_err(|_| Failure::AuthorityDenied)?;
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
        uid,
        effective_uid: uid,
        gid: caller.peer.gid,
        supplementary_groups: groups,
        user_session: Some(dev_tools_privilege_session::linux::UserSession { umask }),
        controlling_terminal: execution.terminal,
        inherited_files: Vec::new(),
    };
    let executable = program
        .file
        .try_clone()
        .map_err(|_| Failure::RuntimeFailure)?;
    state
        .registry
        .issue(
            id,
            scope.clone(),
            request.authority.clone(),
            limits,
            None,
            now,
        )
        .map_err(session_failure)?;
    progress.changed();
    eprintln!(
        "dev-auth grant run: grant={id:032x} uid={uid} program_sha256={}",
        program.sha256
    );
    state.metadata.insert(
        id,
        Metadata {
            request,
            scope: scope.clone(),
            boundary,
            workload: None,
            terminal_since: None,
            launch_owner: None,
        },
    );
    state.attach_job(
        job_id,
        Job {
            grant: id,
            boundary: job_boundary,
            preparing: true,
            leader_done: false,
            external_leader: None,
            origin: scope.clone(),
            relay: RelayAdmission::Ordinary,
            captured: None,
        },
    )?;
    // Control requests from inside the tree select this grant. Sudo routes
    // through the job boundary itself, so no marker is published.
    state.selected.insert(scope, id);
    drop(state);
    let ran = async {
        send_started(connection, deadline, execution.terminal, master)?;
        let spawned = tokio::task::spawn_blocking(move || {
            permit.spawn_held(
                executable,
                &execution.program,
                &execution.arguments,
                &execution.environment,
                context,
                streams,
            )
        })
        .await;
        let child = {
            let mut state = service.state.lock().await;
            let job = state.jobs.get_mut(&job_id).ok_or(Failure::RuntimeFailure)?;
            job.preparing = false;
            let Ok(Ok(child)) = spawned else {
                job.leader_done = true;
                let _ = job.boundary.stop();
                return Err(Failure::RuntimeFailure);
            };
            // The pidfd lets reaping end the grant when the program exits,
            // independent of this task; waiting below is the primary path.
            let leader = rustix::process::pidfd_open(
                rustix::process::Pid::from_child(&child),
                rustix::process::PidfdFlags::empty(),
            );
            if let Ok(leader) = leader {
                job.external_leader = native::clone_fd(&leader).ok();
                state.commands.insert(id, leader);
            }
            child
        };
        drop(setup_lease);
        wait_leader(
            service,
            caller,
            connection,
            &events,
            (job_id, id),
            deadline,
            &child,
        )
        .await
    }
    .await;
    {
        let mut state = service.state.lock().await;
        if let Some(job) = state.jobs.get_mut(&job_id) {
            job.preparing = false;
            job.leader_done = true;
        }
        state
            .registry
            .stop(id, StopReason::WorkloadEnded, self::now()?)
            .map_err(session_failure)?;
    }
    let ended = ended(service, id).await;
    let status = ran?;
    let state = service.state.lock().await;
    let mut response = ControlResult::success("run", true);
    response.child_exit_code = status.code();
    response.child_signal = status.signal();
    response.grant = Some(snapshot(&state, id, self::now()?)?);
    if !ended {
        response.error_kind = Some(Failure::CleanupFailed);
    }
    Ok(response)
}

/// Reap until the stopped grant reaches its terminal state, within the bound
/// that `revoke` uses. Whatever its program left running is stopped with it.
async fn ended(service: &Service, id: GrantId) -> bool {
    settle(service, Some(id)).await.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const PROGRAM: &[u8] = b"\x7fELFfixture program bytes\n";
    /// `printf '\177ELFfixture program bytes\n' | sha256sum`
    const PROGRAM_SHA256: &str = "2719ca1509171f4f3166c0d70092dc7a2fa5ceb838cf587c701581e8a7161181";

    /// A directory that stands in for the caller's root, holding `usr/bin`.
    fn caller_root() -> (tempfile::TempDir, File) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        let handle = File::open(root.path()).unwrap();
        (root, handle)
    }

    /// The account that owns the fixture files.
    fn owner() -> Runner {
        Runner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            groups: Vec::new(),
        }
    }

    fn install(root: &Path, name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let path = root.join("usr/bin").join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_native_program_its_canonical_path_names_is_digested_from_its_descriptor() {
        let (root, handle) = caller_root();
        let path = install(root.path(), "converge", PROGRAM, 0o755);
        let program = Program::verify(
            &handle,
            OsStr::new("/usr/bin/converge"),
            File::open(&path).unwrap(),
            &owner(),
        )
        .unwrap();
        assert_eq!(program.sha256, PROGRAM_SHA256);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (program.device, program.inode),
            (metadata.dev(), metadata.ino())
        );
        assert_eq!(program.owner, metadata.uid());
        assert!(program.unchanged());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"appended after approval")
            .unwrap();
        assert!(!program.unchanged(), "a change after approval is seen");
    }

    #[test]
    fn a_path_that_does_not_name_the_descriptor_exactly_is_refused() {
        let (root, handle) = caller_root();
        let path = install(root.path(), "converge", PROGRAM, 0o755);
        let decoy = install(root.path(), "decoy", PROGRAM, 0o755);
        std::os::unix::fs::symlink("converge", root.path().join("usr/bin/link")).unwrap();
        std::os::unix::fs::symlink("/", root.path().join("escape")).unwrap();
        for (named, opened) in [
            ("/usr/bin/converge", &decoy),
            ("/usr/bin/link", &path),
            ("/escape/usr/bin/converge", &path),
            ("/usr/bin/../bin/converge", &path),
            ("usr/bin/converge", &path),
            ("/usr/bin/absent", &path),
            ("/usr/bin//converge", &path),
            ("/usr/./bin/converge", &path),
            ("/usr/bin/converge/", &path),
        ] {
            assert!(
                Program::verify(
                    &handle,
                    OsStr::new(named),
                    File::open(opened).unwrap(),
                    &owner()
                )
                .is_err(),
                "{named}"
            );
        }
    }

    #[test]
    fn a_program_must_be_opened_read_only_and_be_executable_by_its_runner() {
        let (root, handle) = caller_root();
        let path = install(root.path(), "converge", PROGRAM, 0o700);
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(
            Program::verify(&handle, OsStr::new("/usr/bin/converge"), writable, &owner()).err(),
            Some(Failure::InvalidRequest),
            "a writable descriptor could change the bytes after approval"
        );
        let other = Runner {
            uid: owner().uid.wrapping_add(1),
            gid: owner().gid.wrapping_add(1),
            groups: Vec::new(),
        };
        assert_eq!(
            Program::verify(
                &handle,
                OsStr::new("/usr/bin/converge"),
                File::open(&path).unwrap(),
                &other
            )
            .err(),
            Some(Failure::InvalidRequest),
            "only the owner may execute a 0700 program"
        );
        assert!(Program::verify(
            &handle,
            OsStr::new("/usr/bin/converge"),
            File::open(&path).unwrap(),
            &owner()
        )
        .is_ok());
    }

    #[test]
    fn only_an_executable_regular_elf_file_is_a_program() {
        let (root, handle) = caller_root();
        for (name, bytes, mode) in [
            ("script", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
            ("plain", PROGRAM, 0o644),
            ("short", b"\x7fEL".as_slice(), 0o755),
        ] {
            let path = install(root.path(), name, bytes, mode);
            assert_eq!(
                Program::verify(
                    &handle,
                    OsStr::new(&format!("/usr/bin/{name}")),
                    File::open(path).unwrap(),
                    &owner()
                )
                .err(),
                Some(Failure::InvalidRequest),
                "{name}"
            );
        }
        let directory = root.path().join("usr/bin");
        assert!(Program::verify(
            &handle,
            OsStr::new("/usr/bin"),
            File::open(directory).unwrap(),
            &owner()
        )
        .is_err());
    }
}
