//! The owning parent observes the final native exec before target instructions.
//! No caller-selected PID or signal hint enters this barrier.
use super::*;

pub(super) fn prepare(command: &mut Command) -> Result<()> {
    let parent_pid = std::process::id() as nix::libc::pid_t;
    let parent = rustix::process::pidfd_open(
        rustix::process::getpid(),
        rustix::process::PidfdFlags::empty(),
    )
    .context("retain final exec barrier parent identity")?;
    // Tracing changes exec's set-ID/file-capability semantics. Refuse those
    // configured launchers instead of silently running a different identity.
    let metadata = fs::metadata(command.get_program())?;
    if metadata.mode() & 0o6000 != 0 {
        bail!("launch grant barrier does not support set-ID launchers");
    }
    let path = CString::new(command.get_program().as_bytes())?;
    // SAFETY: both names are terminated, valid for the call; zero length and
    // null output query only the capability attribute's size, not its bytes.
    let capabilities = unsafe {
        nix::libc::getxattr(
            path.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if capabilities > 0 {
        bail!("launch grant barrier does not support capability-bearing launchers");
    }
    if capabilities < 0
        && !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ENODATA | nix::libc::ENOTSUP)
        )
    {
        return Err(std::io::Error::last_os_error())
            .context("inspect configured launcher execution identity");
    }
    // SAFETY: this child callback makes only the native ptrace syscall before
    // exec, without allocation, locks or shared Rust state. TRACEME asks the
    // child's actual parent to own its exec stop; it never attaches to a PID.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut observation = nix::libc::pollfd {
                fd: parent.as_raw_fd(),
                events: nix::libc::POLLIN,
                revents: 0,
            };
            if nix::libc::getppid() != parent_pid || nix::libc::poll(&mut observation, 1, 0) != 0 {
                return Err(std::io::Error::from_raw_os_error(nix::libc::EPIPE));
            }
            if nix::libc::ptrace(
                nix::libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<nix::libc::c_void>(),
                std::ptr::null_mut::<nix::libc::c_void>(),
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn await_exec(child: &Child) -> Result<()> {
    let deadline = Instant::now() + STARTUP_PROOF_TIMEOUT;
    loop {
        // SAFETY: waitid initializes this siginfo output and only observes the
        // exact still-owned child. WNOWAIT preserves sole reaping ownership and
        // prevents PID reuse even when the child exits during startup.
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            nix::libc::waitid(
                nix::libc::P_PID,
                child.id(),
                &mut info,
                nix::libc::WEXITED | nix::libc::WSTOPPED | nix::libc::WNOWAIT | nix::libc::WNOHANG,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("observe owned final exec barrier");
        }
        // SAFETY: the successful waitid filled the native siginfo union.
        if unsafe { info.si_pid() } != 0 {
            if info.si_code != nix::libc::CLD_TRAPPED
                || unsafe { info.si_status() } != nix::libc::SIGTRAP
            {
                bail!("configured target did not reach its final exec stop");
            }
            // SAFETY: SETOPTIONS acts only on our still-owned stopped child;
            // the data word is the documented option bitmask, never a pointer.
            if unsafe {
                nix::libc::ptrace(
                    nix::libc::PTRACE_SETOPTIONS,
                    child.id() as nix::libc::pid_t,
                    std::ptr::null_mut::<nix::libc::c_void>(),
                    nix::libc::PTRACE_O_EXITKILL as usize,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("retain final exec barrier custody");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("final exec barrier timed out");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn release(child: &Child) -> Result<()> {
    // SAFETY: the owning parent detaches its exact unreaped child at the exec
    // stop. Zero signal suppresses the synthetic exec trap. Failure never
    // releases another process and leaves cleanup with the existing owner.
    if unsafe {
        nix::libc::ptrace(
            nix::libc::PTRACE_DETACH,
            child.id() as nix::libc::pid_t,
            std::ptr::null_mut::<nix::libc::c_void>(),
            std::ptr::null_mut::<nix::libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("release owned final exec barrier");
    }
    Ok(())
}
