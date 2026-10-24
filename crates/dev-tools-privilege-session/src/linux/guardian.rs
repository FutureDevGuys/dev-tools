//! A separately owned kernel-timer process; stopping the coordinator does not
//! stop this process. The product's service manager owns whole-unit crash cleanup.
//!
//! The guardian waits for its boundary's admission gate to close or its hard
//! deadline to pass. At the deadline it closes the gate itself. It then writes
//! `cgroup.kill` once the grace has passed since the first of the two, or exits
//! as soon as the boundary is empty (ADR 0141).

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
    /// `events` is the boundary's `cgroup.events`, opened for this guardian
    /// alone. `grace` separates the end of admission from `cgroup.kill`.
    pub(super) fn start(
        kill: File,
        gate: OwnedFd,
        events: File,
        deadline: Duration,
        grace: Duration,
    ) -> io::Result<Self> {
        let after_deadline = deadline
            .checked_add(grace)
            .filter(|kill_at| *kill_at <= super::MAX_BOOT_DEADLINE);
        let Some(after_deadline) = after_deadline.filter(|_| {
            !grace.is_zero() && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        }) else {
            return Err(io::Error::other(
                "deadline guardian clock or target is unsupported",
            ));
        };
        let after_deadline = timespec(after_deadline);
        let grace = timespec(grace);
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
            events.as_raw_fd() as u32,
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
            // SAFETY: all five distinct descriptors and the sorted keep list
            // were prepared before clone and remain open in this child's table.
            unsafe {
                run_child(
                    Held {
                        kill: kill.as_raw_fd(),
                        gate: gate.as_raw_fd(),
                        timer: timer.as_fd().as_raw_fd(),
                        events: events.as_raw_fd(),
                        ready: ready_write.as_raw_fd(),
                    },
                    keep,
                    after_deadline,
                    grace,
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

    /// Reap this guardian if it has exited, without waiting for it. A reaped
    /// guardian reports its outcome as `join` does.
    pub(super) fn try_join(&mut self) -> io::Result<bool> {
        if !self.reaped && !self.wait_until(Instant::now())? {
            return Ok(false);
        }
        self.outcome().map(|()| true)
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

fn timespec(time: Duration) -> nix::libc::timespec {
    nix::libc::timespec {
        tv_sec: time.as_secs() as nix::libc::time_t,
        tv_nsec: time.subsec_nanos() as nix::libc::c_long,
    }
}

/// The descriptors a guardian child holds.
#[derive(Clone, Copy)]
struct Held {
    kill: i32,
    gate: i32,
    timer: i32,
    events: i32,
    ready: i32,
}

/// Run only in the fork-like clone child while every catchable signal is blocked.
/// `keep` is sorted, distinct and contains the five live, owned descriptor numbers.
/// No Rust allocation, locks, destructors, panic path or foreign callback may run.
unsafe fn run_child(
    held: Held,
    keep: [u32; 5],
    after_deadline: nix::libc::timespec,
    grace: nix::libc::timespec,
) -> ! {
    let Held {
        kill,
        gate,
        timer,
        events,
        ready,
    } = held;
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
    if unsafe { wait(&mut descriptors) } <= 0 {
        unsafe { finish_child(kill, gate, false) }
    }
    let expired = descriptors[1].revents != 0;
    if expired && !unsafe { close_gate(gate) } {
        unsafe { finish_child(kill, gate, false) }
    }
    let schedule = nix::libc::itimerspec {
        it_interval: nix::libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: if expired { after_deadline } else { grace },
    };
    // SAFETY: the held timer is re-armed from one initialized local value; a
    // relative grace starts now, and the deadline's grace is absolute.
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_timerfd_settime,
            timer,
            if expired {
                nix::libc::TFD_TIMER_ABSTIME
            } else {
                0
            },
            &schedule as *const nix::libc::itimerspec,
            std::ptr::null_mut::<nix::libc::itimerspec>(),
        )
    } != 0
    {
        unsafe { finish_child(kill, gate, false) }
    }
    loop {
        // SAFETY: events is this guardian's own held cgroup.events description.
        if unsafe { populated(events) } == Some(false) {
            break;
        }
        let mut descriptors = [
            nix::libc::pollfd {
                fd: timer,
                events: nix::libc::POLLIN,
                revents: 0,
            },
            nix::libc::pollfd {
                fd: events,
                events: nix::libc::POLLPRI,
                revents: 0,
            },
        ];
        // SAFETY: as above; a population change notifies cgroup.events with
        // POLLPRI, so each wake reads the population again.
        if unsafe { wait(&mut descriptors) } <= 0 {
            unsafe { finish_child(kill, gate, false) }
        }
        if descriptors[0].revents != 0 {
            break;
        }
    }
    unsafe { finish_child(kill, gate, true) }
}

/// Wait without a timeout until a polled descriptor is ready.
unsafe fn wait(descriptors: &mut [nix::libc::pollfd; 2]) -> nix::libc::c_long {
    // SAFETY: the caller's initialized array stays borrowed for the call.
    unsafe {
        nix::libc::syscall(
            nix::libc::SYS_ppoll,
            descriptors.as_mut_ptr(),
            2_usize,
            std::ptr::null::<nix::libc::timespec>(),
            std::ptr::null::<u64>(),
            std::mem::size_of::<u64>(),
        )
    }
}

/// Close the admission gate. A saturated eventfd is already closed.
unsafe fn close_gate(gate: i32) -> bool {
    let value = 1_u64;
    // SAFETY: eventfd consumes one initialized native u64 synchronously.
    let written =
        unsafe { nix::libc::syscall(nix::libc::SYS_write, gate, &value as *const u64, 8_usize) };
    written == 8 || (written < 0 && unsafe { *nix::libc::__errno_location() } == nix::libc::EAGAIN)
}

/// One read of the boundary's population: `Some(false)` once it has no
/// member, and `None` when the read or its content cannot be used.
unsafe fn populated(events: i32) -> Option<bool> {
    let mut bytes = [0_u8; 256];
    // SAFETY: pread fills only the initialized local buffer.
    let length = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pread64,
            events,
            bytes.as_mut_ptr(),
            bytes.len(),
            0_i64,
        )
    };
    let text = bytes.get(..usize::try_from(length).ok()?)?;
    if text.len() == bytes.len() {
        return None;
    }
    let mut population = None;
    for line in text.split(|byte| *byte == b'\n') {
        match line {
            b"populated 0" => population = Some(false),
            b"populated 1" => population = Some(true),
            _ => {}
        }
    }
    population
}

/// Held gate and cgroup.kill belong to exactly one freshly prepared boundary.
/// This child has no other execution path and must terminate through _exit.
unsafe fn finish_child(kill: i32, gate: i32, observed: bool) -> ! {
    // SAFETY: the held gate descriptor stays open until _exit.
    let revoked = unsafe { close_gate(gate) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::eventfd::{EfdFlags, EventFd};
    use std::path::PathBuf;

    const GRACE: Duration = Duration::from_millis(400);

    /// Ordinary files that stand in for a boundary's `cgroup.kill` and
    /// `cgroup.events`, and the boundary's admission gate.
    struct Boundary {
        _directory: tempfile::TempDir,
        kill: PathBuf,
        events: PathBuf,
        gate: EventFd,
    }

    impl Boundary {
        fn new(populated: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let kill = directory.path().join("cgroup.kill");
            let events = directory.path().join("cgroup.events");
            std::fs::write(&kill, b"").unwrap();
            std::fs::write(
                &events,
                format!("populated {}\nfrozen 0\n", u8::from(populated)),
            )
            .unwrap();
            Self {
                _directory: directory,
                kill,
                events,
                gate: EventFd::from_value_and_flags(
                    0,
                    EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK,
                )
                .unwrap(),
            }
        }

        fn guard(&self, deadline: Duration) -> DeadlineGuard {
            DeadlineGuard::start(
                File::options().write(true).open(&self.kill).unwrap(),
                self.gate.as_fd().try_clone_to_owned().unwrap(),
                File::open(&self.events).unwrap(),
                deadline,
                GRACE,
            )
            .unwrap()
        }

        fn close_gate(&self) {
            self.gate.write(1).unwrap();
        }

        fn gate_closed(&self) -> bool {
            let mut descriptor = [nix::poll::PollFd::new(
                self.gate.as_fd(),
                nix::poll::PollFlags::POLLIN,
            )];
            nix::poll::poll(&mut descriptor, nix::poll::PollTimeout::ZERO).unwrap() == 1
        }

        fn killed(&self) -> bool {
            std::fs::read(&self.kill).unwrap() == b"1"
        }
    }

    fn from_now(delay: Duration) -> Duration {
        super::super::boot_time().unwrap() + delay
    }

    #[test]
    fn a_closed_gate_leaves_the_members_their_grace_before_the_kill() {
        let boundary = Boundary::new(true);
        let mut guard = boundary.guard(from_now(Duration::from_secs(60)));
        let closed = Instant::now();
        boundary.close_gate();
        std::thread::sleep(GRACE / 2);
        assert!(!boundary.killed(), "the members still have the grace");
        guard.join().unwrap();
        assert!(boundary.killed());
        assert!(closed.elapsed() >= GRACE, "{:?}", closed.elapsed());
    }

    #[test]
    fn an_empty_boundary_releases_its_guardian_at_once() {
        let boundary = Boundary::new(false);
        let mut guard = boundary.guard(from_now(Duration::from_secs(60)));
        let closed = Instant::now();
        boundary.close_gate();
        guard.join().unwrap();
        assert!(closed.elapsed() < GRACE, "{:?}", closed.elapsed());
    }

    #[test]
    fn the_deadline_closes_admission_and_kills_after_the_grace() {
        let boundary = Boundary::new(true);
        let deadline = from_now(Duration::from_millis(200));
        let mut guard = boundary.guard(deadline);
        while super::super::boot_time().unwrap() < deadline + GRACE / 4 {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(boundary.gate_closed(), "admission closes at the deadline");
        assert!(
            !boundary.killed(),
            "the members have the grace after the deadline"
        );
        guard.join().unwrap();
        assert!(boundary.killed());
        assert!(super::super::boot_time().unwrap() >= deadline + GRACE);
    }
}
