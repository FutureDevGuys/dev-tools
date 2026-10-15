//! A separately owned kernel-timer process; stopping the coordinator does not
//! stop this process. The product's service manager owns whole-unit crash cleanup.

use nix::sys::timerfd::{ClockId, TimerFd, TimerFlags, TimerSetTimeFlags};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const STARTUP_WAIT: Duration = Duration::from_secs(2);
const JOIN_WAIT: Duration = Duration::from_secs(2);

/// Linux UAPI clone_args uses eleven 64-bit slots, including pointer values.
/// CLONE_PIDFD creates this direct child and its identity handle atomically.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

// Supported x86_64/aarch64 Linux UAPI: clone_args is eleven aligned u64 slots,
// and rt_sigprocmask accepts an eight-byte kernel signal set. Other targets fail
// before clone. These layout facts do not establish native syscall availability.
const _: () = assert!(std::mem::size_of::<CloneArgs>() == 88);

pub(super) struct DeadlineGuard {
    pid: nix::libc::pid_t,
    pidfd: OwnedFd,
    reaped: bool,
    cleanup_failed: bool,
}

impl DeadlineGuard {
    pub(super) fn admission_gate(&self) -> io::Result<OwnedFd> {
        let mut descriptor = [nix::poll::PollFd::new(
            self.pidfd.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        if self.reaped || nix::poll::poll(&mut descriptor, nix::poll::PollTimeout::ZERO)? != 0 {
            return Err(io::Error::other("deadline guardian is no longer running"));
        }
        self.pidfd.as_fd().try_clone_to_owned()
    }

    /// The parent must exclusively own direct-child reaping and keep SIGCHLD's
    /// disposition stable while this owner exists. The checked boundary creates
    /// the guardian before exposing a fresh target cgroup to any admission;
    /// the guardian remains in the coordinator's outer service cgroup.
    pub(super) fn start(kill: File, gate: OwnedFd, deadline: Duration) -> io::Result<Self> {
        if deadline > super::MAX_BOOT_DEADLINE
            || !cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        {
            return Err(io::Error::other(
                "deadline guardian clock or target is unsupported",
            ));
        }
        // SAFETY: sigaction writes one initialized local structure; this is a
        // query only. Automatic reaping cannot provide the required join proof.
        let mut disposition: nix::libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { nix::libc::sigaction(nix::libc::SIGCHLD, std::ptr::null(), &mut disposition) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        if disposition.sa_sigaction == nix::libc::SIG_IGN
            || disposition.sa_flags & nix::libc::SA_NOCLDWAIT != 0
        {
            return Err(io::Error::other(
                "deadline guardian requires owned child reaping",
            ));
        }
        let timer = TimerFd::new(
            ClockId::CLOCK_BOOTTIME,
            TimerFlags::TFD_CLOEXEC | TimerFlags::TFD_NONBLOCK,
        )?;
        timer.set(
            nix::sys::timer::Expiration::OneShot(nix::sys::time::TimeSpec::from_duration(deadline)),
            TimerSetTimeFlags::TFD_TIMER_ABSTIME,
        )?;
        let (ready_read, ready_write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK)?;
        let mut keep = [
            kill.as_raw_fd() as u32,
            gate.as_raw_fd() as u32,
            timer.as_fd().as_raw_fd() as u32,
            ready_write.as_raw_fd() as u32,
        ];
        keep.sort_unstable();
        if keep[0] < 3 || keep.windows(2).any(|fds| fds[0] == fds[1]) {
            return Err(io::Error::other(
                "deadline guardian descriptors are invalid",
            ));
        }
        let mut descriptor = -1_i32;
        let args = CloneArgs {
            flags: nix::libc::CLONE_PIDFD as u64,
            pidfd: (&mut descriptor as *mut i32) as usize as u64,
            exit_signal: nix::libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        // Block this thread before clone, so the child cannot enter any inherited
        // Rust/foreign signal handler between clone return and its raw loop.
        // Other coordinator threads retain their own masks.
        let mut mask = SignalMask::block()?;
        // SAFETY: fork-like clone3 has no shared VM/stack or callback. args and
        // its writable pidfd slot are initialized and live for the syscall.
        // The child calls only raw async-signal-safe operations then _exit;
        // it cannot return through Rust destructors or unwind across this frame.
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_clone3,
                &args as *const CloneArgs,
                std::mem::size_of::<CloneArgs>(),
            )
        };
        if result == 0 {
            // SAFETY: all four distinct descriptors and the sorted keep list
            // were prepared before clone and remain open in this child's table.
            unsafe {
                run_child(
                    kill.as_raw_fd(),
                    gate.as_raw_fd(),
                    timer.as_fd().as_raw_fd(),
                    ready_write.as_raw_fd(),
                    keep,
                )
            }
        }
        let clone_error = (result < 0).then(io::Error::last_os_error);
        let restored = mask.restore();
        if let Some(error) = clone_error {
            restored?;
            return Err(error);
        }
        // CLONE_PIDFD success guarantees a newly owned nonnegative pidfd in the
        // supplied slot. A kernel ABI violation cannot be treated as authority.
        assert!(
            descriptor >= 0,
            "clone3 must return its requested child pidfd"
        );
        // SAFETY: the kernel transferred one new pidfd on successful clone3.
        let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let mut guard = Self {
            pid: result as nix::libc::pid_t,
            pidfd,
            reaped: false,
            cleanup_failed: false,
        };
        drop(ready_write);
        if let Err(error) = restored {
            guard.force_stop();
            let _ = guard.join();
            return Err(error);
        }
        let ready = read_ready(ready_read);
        if let Err(error) = ready {
            guard.force_stop();
            let _ = guard.join();
            return Err(error);
        }
        Ok(guard)
    }

    /// Join is bounded and remembers a forced stop, failed status or lost reap.
    /// A failure cannot be turned into successful boundary removal on retry.
    pub(super) fn join(&mut self) -> io::Result<()> {
        if self.reaped {
            return self.outcome();
        }
        if self.wait_until(Instant::now() + JOIN_WAIT)? {
            return self.outcome();
        }
        self.force_stop();
        if !self.wait_until(Instant::now() + JOIN_WAIT)? {
            return Err(io::Error::other(
                "deadline guardian join could not be proven",
            ));
        }
        self.outcome()
    }

    fn wait_until(&mut self, deadline: Instant) -> io::Result<bool> {
        loop {
            let mut status = 0_i32;
            // SAFETY: pid is our unreaped direct child and status is local output.
            // The owner never signals a bare PID and never installs SIGCHLD hooks.
            let result = unsafe { nix::libc::waitpid(self.pid, &mut status, nix::libc::WNOHANG) };
            if result == self.pid {
                self.reaped = true;
                if !nix::libc::WIFEXITED(status) || nix::libc::WEXITSTATUS(status) != 0 {
                    self.cleanup_failed = true;
                }
                return Ok(true);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(nix::libc::EINTR) {
                    self.cleanup_failed = true;
                    self.force_stop();
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn force_stop(&mut self) {
        self.cleanup_failed = true;
        if !self.reaped {
            // The atomically retained pidfd identifies only this guardian,
            // including if another component violated exclusive reap ownership.
            let _ = super::signal_pidfd(&self.pidfd, nix::sys::signal::Signal::SIGKILL);
        }
    }

    fn outcome(&self) -> io::Result<()> {
        if self.cleanup_failed {
            Err(io::Error::other("deadline guardian cleanup failed"))
        } else {
            Ok(())
        }
    }
}

impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        if !self.reaped {
            self.force_stop();
            let _ = self.wait_until(Instant::now() + JOIN_WAIT);
        }
    }
}

fn read_ready(descriptor: OwnedFd) -> io::Result<()> {
    let deadline = Instant::now() + STARTUP_WAIT;
    let mut file = File::from(descriptor);
    loop {
        let mut byte = [0_u8; 1];
        match file.read(&mut byte) {
            Ok(1) if byte[0] == 1 => return Ok(()),
            Ok(0) => {
                return Err(io::Error::other(
                    "deadline guardian failed before readiness",
                ))
            }
            Ok(_) => return Err(io::Error::other("deadline guardian readiness is invalid")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("deadline guardian readiness timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct SignalMask {
    previous: u64,
    restored: bool,
}

impl SignalMask {
    fn block() -> io::Result<Self> {
        let mut previous = 0_u64;
        let all = u64::MAX;
        // SAFETY: Linux rt_sigprocmask's kernel signal set is one 64-bit word.
        // Both slots are initialized and borrowed only by this synchronous call.
        if unsafe {
            nix::libc::syscall(
                nix::libc::SYS_rt_sigprocmask,
                nix::libc::SIG_SETMASK,
                &all as *const u64,
                &mut previous as *mut u64,
                std::mem::size_of::<u64>(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            previous,
            restored: false,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        // SAFETY: previous was returned by the same calling thread's mask change.
        if unsafe {
            nix::libc::syscall(
                nix::libc::SYS_rt_sigprocmask,
                nix::libc::SIG_SETMASK,
                &self.previous as *const u64,
                std::ptr::null_mut::<u64>(),
                std::mem::size_of::<u64>(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for SignalMask {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Run only in the fork-like clone child while every catchable signal is blocked.
/// `keep` is sorted, distinct and contains the four live, owned descriptor numbers.
/// No Rust allocation, locks, destructors, panic path or foreign callback may run.
unsafe fn run_child(kill: i32, gate: i32, timer: i32, ready: i32, keep: [u32; 4]) -> ! {
    let mut first = 0_u32;
    for retained in keep {
        if first < retained {
            // SAFETY: close_range operates only on this child's descriptor table,
            // excluding every named held resource prepared by the parent.
            if unsafe { nix::libc::syscall(nix::libc::SYS_close_range, first, retained - 1, 0_u32) }
                != 0
            {
                // SAFETY: held gate/kill descriptors have not been closed.
                unsafe { finish_child(kill, gate, false) }
            }
        }
        first = retained + 1;
    }
    // SAFETY: the tail is outside every retained descriptor; no parent handles
    // are affected and inherited sockets/terminals cannot be held open here.
    if unsafe { nix::libc::syscall(nix::libc::SYS_close_range, first, u32::MAX, 0_u32) } != 0 {
        unsafe { finish_child(kill, gate, false) }
    }
    let byte = 1_u8;
    // SAFETY: ready is the private inherited nonblocking pipe writer and byte
    // remains initialized and live for this synchronous write.
    if unsafe { nix::libc::syscall(nix::libc::SYS_write, ready, &byte as *const u8, 1_usize) } != 1
    {
        unsafe { finish_child(kill, gate, false) }
    }
    unsafe { nix::libc::syscall(nix::libc::SYS_close, ready) };
    let mut descriptors = [
        nix::libc::pollfd {
            fd: gate,
            events: nix::libc::POLLIN,
            revents: 0,
        },
        nix::libc::pollfd {
            fd: timer,
            events: nix::libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: the initialized native pollfd array stays local; only held gate
    // and absolute CLOCK_BOOTTIME timer descriptors are polled. Signals stay
    // blocked, so inherited process handlers never run in this guardian.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_ppoll,
            descriptors.as_mut_ptr(),
            2_usize,
            std::ptr::null::<nix::libc::timespec>(),
            std::ptr::null::<u64>(),
            std::mem::size_of::<u64>(),
        )
    };
    unsafe { finish_child(kill, gate, result > 0) }
}

/// Held gate and cgroup.kill belong to exactly one freshly prepared boundary.
/// This child has no other execution path and must terminate through _exit.
unsafe fn finish_child(kill: i32, gate: i32, observed: bool) -> ! {
    let value = 1_u64;
    // SAFETY: eventfd consumes one initialized native u64 synchronously.
    let written =
        unsafe { nix::libc::syscall(nix::libc::SYS_write, gate, &value as *const u64, 8_usize) };
    // A saturated eventfd is already permanently readable; no holder reads it.
    let revoked = written == 8
        || (written < 0 && unsafe { *nix::libc::__errno_location() } == nix::libc::EAGAIN);
    let byte = b'1';
    // SAFETY: pwrite uses the retained cgroup.kill descriptor and one initialized
    // byte, without pathname lookup or access to another grant's kernel domain.
    let killed = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pwrite64,
            kill,
            &byte as *const u8,
            1_usize,
            0_u64,
        )
    } == 1;
    // SAFETY: _exit ends this raw child without Rust/foreign teardown or unwinding.
    unsafe { nix::libc::_exit(if observed && revoked && killed { 0 } else { 1 }) }
}
