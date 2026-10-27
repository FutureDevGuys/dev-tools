//! Linux calling-thread signal and controlling-terminal custody shared by the
//! inherited runner and the additive foreground graph runner. No global handlers.
use crate::ProcessDomain;
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::rc::Rc;
use std::time::Duration;

/// Exclusive, calling-thread custody of the inherited controlling terminal.
///
/// The caller serializes terminal users and suspends its own terminal reads and
/// rendering before opening this guard. The guard changes only this thread's
/// SIGTTOU mask and no process-wide disposition. It neither authorizes nor reaps
/// commands, forwards signals, enforces deadlines, or contains descendants.
/// The caller owns the child until terminal custody has been restored.
///
/// This guard is deliberately neither Send nor Sync because its saved signal
/// mask belongs to the opening thread. `restore` reports restoration errors;
/// dropping the guard performs the same restoration as a best-effort fallback.
pub struct ForegroundTerminal {
    terminal: Option<Terminal>,
    attributes: libc::termios,
    previous_mask: libc::sigset_t,
    mask_active: bool,
    unblock_child_sigttou: bool,
    _calling_thread: PhantomData<Rc<()>>,
}

impl ForegroundTerminal {
    /// Retain the current terminal and require the caller's foreground group.
    /// Returns None only when the caller has no controlling terminal.
    pub fn open() -> Result<Option<Self>> {
        let Some(terminal) = Terminal::open()? else {
            return Ok(None);
        };
        terminal.require_foreground()?;
        // SAFETY: termios and sigset_t are initialized POD output objects.
        let (mut attributes, mut mask, mut previous_mask) =
            unsafe { (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed()) };
        // SAFETY: the retained file names this thread's controlling terminal.
        if unsafe { libc::tcgetattr(terminal.file.as_raw_fd(), &mut attributes) } != 0 {
            return Err(io::Error::last_os_error()).context("save terminal attributes");
        }
        // SAFETY: initialized native masks are borrowed only during these calls.
        let error = unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous_mask)
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error))
                .context("block terminal handoff signal");
        }
        // SAFETY: the successful native exchange initialized previous_mask.
        let unblock_child_sigttou =
            unsafe { libc::sigismember(&previous_mask, libc::SIGTTOU) } == 0;
        Ok(Some(Self {
            terminal: Some(terminal),
            attributes,
            previous_mask,
            mask_active: true,
            unblock_child_sigttou,
            _calling_thread: PhantomData,
        }))
    }

    /// Prepare a dedicated child group without inheriting the guard's SIGTTOU
    /// block. Invoke once before spawn; other prepared callbacks stay intact.
    pub fn prepare_child(&self, command: &mut Command) {
        command.process_group(0);
        if self.unblock_child_sigttou {
            // SAFETY: the child callback uses only async-signal-safe native mask
            // operations and captures no parent references or allocation.
            unsafe {
                command.pre_exec(|| {
                    let mut mask = std::mem::zeroed();
                    libc::sigemptyset(&mut mask);
                    libc::sigaddset(&mut mask, libc::SIGTTOU);
                    if libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()) == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                });
            }
        }
    }

    /// Transfer foreground ownership to this unreaped direct child's group.
    /// The caller must retain exclusive child reaping and signal ownership.
    pub fn give_to(&mut self, child: &Child) -> Result<()> {
        let group = i32::try_from(child.id()).context("terminal child group is out of range")?;
        let domain = ProcessDomain::for_child(child);
        crate::process_exit_observed(domain).context("terminal child wait custody unavailable")?;
        // SAFETY: the caller retains this direct child's wait identity. These
        // query-only calls cannot affect the process or its group.
        if unsafe { libc::getpgid(group) } != group
            || unsafe { libc::getsid(group) } != unsafe { libc::getsid(0) }
        {
            bail!("terminal child must lead a group in the caller's session");
        }
        self.terminal
            .as_mut()
            .context("terminal custody already restored")?
            .give_to_required(group)
    }

    /// Restore terminal ownership, terminal attributes and the opening thread's
    /// signal mask. All restorations are attempted even if one reports failure.
    pub fn restore(mut self) -> Result<()> {
        self.finish()
    }

    fn finish(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(mut terminal) = self.terminal.take() {
            if let Err(error) = terminal.restore() {
                errors.push(error.to_string());
            }
            // SAFETY: retained original termios and the same live terminal file;
            // SIGTTOU stays blocked through this and Terminal's Drop fallback.
            if unsafe {
                libc::tcsetattr(terminal.file.as_raw_fd(), libc::TCSANOW, &self.attributes)
            } != 0
            {
                errors.push(format!(
                    "restore terminal attributes: {}",
                    io::Error::last_os_error()
                ));
            }
            drop(terminal);
        }
        if self.mask_active {
            // SAFETY: !Send/!Sync retain this initialized mask's opening thread.
            let error = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
            };
            if error == 0 {
                self.mask_active = false;
            } else {
                errors.push(format!(
                    "restore terminal signal mask: {}",
                    io::Error::from_raw_os_error(error)
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("{}", errors.join("; "));
        }
    }
}

impl Drop for ForegroundTerminal {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub(crate) struct Signals {
    pub(crate) previous: libc::sigset_t,
    input: File,
}

impl Signals {
    pub(crate) fn block() -> Result<Self> {
        Self::block_selected(false)
    }

    pub(crate) fn block_job_control() -> Result<Self> {
        Self::block_selected(true)
    }

    fn block_selected(job_control: bool) -> Result<Self> {
        // SAFETY: sigset_t is a libc POD output object; sigemptyset initializes
        // it before use. pthread_sigmask writes the complete previous mask.
        let (mut mask, mut previous) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
        // SAFETY: both pointers are live sigset_t objects; no pointer is retained.
        unsafe {
            libc::sigemptyset(&mut mask);
            for signal in [
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGQUIT,
                libc::SIGHUP,
                libc::SIGCHLD,
                libc::SIGTTOU,
            ] {
                libc::sigaddset(&mut mask, signal);
            }
            if job_control {
                libc::sigaddset(&mut mask, libc::SIGTSTP);
                libc::sigaddset(&mut mask, libc::SIGCONT);
            }
            let error = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous);
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error).into());
            }
        }
        // SAFETY: mask is initialized and borrowed only during signalfd. A
        // successful call transfers one new descriptor to this owner.
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: previous was initialized by successful pthread_sigmask.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
            return Err(error.into());
        }
        // SAFETY: fd is a fresh owned descriptor returned above, not aliased
        // by another Rust owner. File closes it exactly once.
        Ok(Self {
            previous,
            input: unsafe { File::from_raw_fd(fd) },
        })
    }

    pub(crate) fn forward(&mut self, child: i32) -> Result<()> {
        self.observe_pending(|signal| {
            if matches!(
                signal,
                libc::SIGINT | libc::SIGTERM | libc::SIGQUIT | libc::SIGHUP
            ) {
                signal_group(child, signal)?;
            }
            Ok(())
        })
    }

    pub(crate) fn drain(&mut self) -> Result<Vec<i32>> {
        let mut pending = Vec::new();
        self.observe_pending(|signal| {
            pending.push(signal);
            Ok(())
        })?;
        Ok(pending)
    }

    fn observe_pending(&mut self, mut observe: impl FnMut(i32) -> Result<()>) -> Result<()> {
        let mut bytes = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
        for _ in 0..64 {
            match self.input.read(&mut bytes) {
                Ok(length) if length == bytes.len() => {
                    let signal = u32::from_ne_bytes(
                        bytes[..4]
                            .try_into()
                            .context("invalid native signal field")?,
                    );
                    observe(i32::try_from(signal)?)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                _ => bail!("native signal observation failed"),
            }
        }
        Ok(())
    }

    pub(crate) fn wait(&self, maximum: Duration) -> Result<()> {
        let mut input = libc::pollfd {
            fd: self.input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = i32::try_from(maximum.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one live initialized pollfd, borrowed during this bounded call.
        let result = unsafe { libc::poll(&mut input, 1, timeout) };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error()).context("wait for native signal state");
        }
        if result > 0 && input.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            bail!("native signal descriptor unavailable");
        }
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        // SAFETY: previous was initialized by this calling thread's mask exchange.
        let error = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error).into());
        }
        Ok(())
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        // SAFETY: previous belongs to this thread's successful mask exchange.
        // Restoration changes no process-wide signal disposition or handler.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

pub(crate) struct Terminal {
    file: File,
    parent: i32,
    changed: bool,
}

impl Terminal {
    pub(crate) fn open() -> Result<Option<Self>> {
        let file = match File::options()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
            .open("/dev/tty")
        {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENXIO | libc::ENOENT | libc::ENODEV)
                ) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error).context("open inherited controlling terminal"),
        };
        // SAFETY: getpgrp has no pointer arguments or memory preconditions.
        Ok(Some(Self {
            file,
            parent: unsafe { libc::getpgrp() },
            changed: false,
        }))
    }

    pub(crate) fn require_foreground(&self) -> Result<()> {
        // SAFETY: the retained descriptor is the current controlling terminal.
        let foreground = unsafe { libc::tcgetpgrp(self.file.as_raw_fd()) };
        if foreground < 0 {
            return Err(io::Error::last_os_error()).context("observe terminal foreground group");
        }
        if foreground != self.parent {
            bail!("terminal graph requires launcher foreground ownership");
        }
        Ok(())
    }

    pub(crate) fn give_to_required(&mut self, child: i32) -> Result<()> {
        self.require_foreground()?;
        // SAFETY: caller has retained this child's native group and the current
        // foreground terminal owner. SIGTTOU remains blocked on this thread.
        if unsafe { libc::tcsetpgrp(self.file.as_raw_fd(), child) } != 0 {
            return Err(io::Error::last_os_error()).context("transfer terminal graph foreground");
        }
        self.changed = true;
        // SAFETY: query the same held controlling-terminal descriptor.
        if unsafe { libc::tcgetpgrp(self.file.as_raw_fd()) } != child {
            bail!("terminal graph foreground transfer was not retained");
        }
        Ok(())
    }

    pub(crate) fn give_to(&mut self, child: i32) -> Result<()> {
        // SAFETY: file retains a live controlling-terminal descriptor.
        let foreground = unsafe { libc::tcgetpgrp(self.file.as_raw_fd()) };
        if foreground < 0 {
            return Err(io::Error::last_os_error()).context("observe terminal foreground group");
        }
        if foreground == self.parent {
            // SAFETY: this process is in the terminal's session and child is
            // its retained process group. SIGTTOU is blocked on this thread.
            if unsafe { libc::tcsetpgrp(self.file.as_raw_fd(), child) } != 0 {
                return Err(io::Error::last_os_error())
                    .context("transfer terminal foreground group");
            }
            self.changed = true;
        }
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        if self.changed {
            // SAFETY: parent is the original native process group and the
            // retained terminal descriptor remains open. SIGTTOU is blocked.
            if unsafe { libc::tcsetpgrp(self.file.as_raw_fd(), self.parent) } != 0 {
                return Err(io::Error::last_os_error())
                    .context("restore terminal foreground group");
            }
            self.changed = false;
        }
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(crate) fn signal_group(group: i32, signal: i32) -> Result<()> {
    let domain = ProcessDomain {
        group: rustix::process::Pid::from_raw(group),
    };
    // A WNOWAIT observation must still identify our retained direct child.
    // Never signal a bare numeric group after wait ownership was lost.
    crate::process_exit_observed(domain).context("native child wait ownership unavailable")?;
    // SAFETY: group is a positive unreaped child PID made into its own group
    // before exec; negation selects only that owned native group.
    if unsafe { libc::kill(-group, signal) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}
