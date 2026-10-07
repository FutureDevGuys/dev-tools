//! Kernel-enforced absolute boot-time backstop for the dedicated coordinator.
//! SIGKILL remains deliverable while the coordinator/foreground is stopped. Its
//! receipt-owned systemd unit must use KillMode=control-group, so coordinator
//! death terminalizes payload domains. The ordinary actor still performs clean
//! teardown first; this backstop never fabricates a successful cleanup report.
use anyhow::{Context, Result};

pub struct HardDeadline {
    timer: nix::libc::timer_t,
    hard_ceiling_ms: u64,
}
impl HardDeadline {
    pub fn arm(absolute_boot_ms: u64) -> Result<Self> {
        let seconds = i64::try_from(absolute_boot_ms / 1000)
            .context("administrative deadline exceeds kernel range")?;
        // SAFETY: sigevent is initialized before the kernel observes it. The
        // fixed SIGKILL is delivered to this dedicated coordinator only.
        let mut event: nix::libc::sigevent = unsafe { std::mem::zeroed() };
        event.sigev_notify = nix::libc::SIGEV_SIGNAL;
        event.sigev_signo = nix::libc::SIGKILL;
        let mut timer: nix::libc::timer_t = unsafe { std::mem::zeroed() };
        if unsafe { nix::libc::timer_create(nix::libc::CLOCK_BOOTTIME, &mut event, &mut timer) }
            != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("create independent administrative deadline");
        }
        let owner = Self {
            timer,
            hard_ceiling_ms: absolute_boot_ms,
        };
        let value = nix::libc::itimerspec {
            it_interval: nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: nix::libc::timespec {
                tv_sec: seconds,
                tv_nsec: ((absolute_boot_ms % 1000) * 1_000_000) as _,
            },
        };
        // SAFETY: initialized fixed ABI timespec; no previous value requested.
        if unsafe {
            nix::libc::timer_settime(
                timer,
                nix::libc::TIMER_ABSTIME,
                &value,
                std::ptr::null_mut(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("arm independent administrative deadline");
        }
        Ok(owner)
    }

    pub fn observe_next(&mut self, next: std::time::Duration) -> Result<()> {
        let millis = u64::try_from(next.as_millis())
            .context("administrative observation exceeds kernel range")?;
        if millis > self.hard_ceiling_ms || millis == 0 {
            anyhow::bail!("administrative deadline cannot expand approved authority");
        }
        let value = nix::libc::itimerspec {
            it_interval: nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: nix::libc::timespec {
                tv_sec: i64::try_from(millis / 1000)?,
                tv_nsec: ((millis % 1000) * 1_000_000) as _,
            },
        };
        // SAFETY: the fixed native timer identity belongs to this guard; rearming
        // uses an absolute deadline bounded by its immutable approved ceiling.
        if unsafe {
            nix::libc::timer_settime(
                self.timer,
                nix::libc::TIMER_ABSTIME,
                &value,
                std::ptr::null_mut(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("observe independent administrative expiry");
        }
        Ok(())
    }
}
impl Drop for HardDeadline {
    fn drop(&mut self) {
        unsafe {
            nix::libc::timer_delete(self.timer);
        }
    }
}
