//! One accounting implementation shared by finite maintenance and grant facades.

use crate::{Cleanup, GrantLimits, LeaseState, SessionError, StopReason};
use std::num::NonZeroU64;
use std::time::Duration;

pub(crate) struct LifecycleCore {
    limits: GrantLimits,
    hard_deadline: Duration,
    idle_deadline: Duration,
    last_observed: Duration,
    remaining: Option<u64>,
    state: LeaseState,
}

impl LifecycleCore {
    pub(crate) fn new(
        limits: GrantLimits,
        now: Duration,
        uses: Option<NonZeroU64>,
    ) -> Result<Self, SessionError> {
        let hard_deadline = now
            .checked_add(limits.hard_timeout())
            .ok_or(SessionError::InvalidClock)?;
        let idle_deadline = now
            .checked_add(limits.idle_timeout())
            .ok_or(SessionError::InvalidClock)?;
        Ok(Self {
            limits,
            hard_deadline,
            idle_deadline,
            last_observed: now,
            remaining: uses.map(NonZeroU64::get),
            state: LeaseState::Active,
        })
    }

    pub(crate) const fn state(&self) -> LeaseState {
        self.state
    }

    pub(crate) const fn remaining_uses(&self) -> Option<u64> {
        self.remaining
    }

    pub(crate) const fn hard_deadline(&self) -> Duration {
        self.hard_deadline
    }

    pub(crate) const fn limits(&self) -> GrantLimits {
        self.limits
    }

    pub(crate) fn next_deadline(&self) -> Option<Duration> {
        (self.state == LeaseState::Active).then(|| self.hard_deadline.min(self.idle_deadline))
    }

    pub(crate) fn poll(&mut self, now: Duration) -> LeaseState {
        if self.state == LeaseState::Active {
            if now < self.last_observed {
                self.stop(StopReason::ClockRegressed);
            } else {
                self.last_observed = now;
                if now >= self.hard_deadline {
                    self.stop(StopReason::HardExpired);
                } else if now >= self.idle_deadline {
                    self.stop(StopReason::IdleExpired);
                }
            }
        }
        self.state
    }

    pub(crate) fn admit(&mut self, now: Duration) -> Result<(), SessionError> {
        self.require_active(now)?;
        if let Some(remaining) = self.remaining.as_mut() {
            *remaining = remaining
                .checked_sub(1)
                .ok_or(SessionError::UsesExhausted)?;
        }
        self.touch(now);
        Ok(())
    }

    /// Delegation reserves allowance without touching idle expiry or refunding uses.
    pub(crate) fn reserve_uses(
        &mut self,
        now: Duration,
        requested: Option<NonZeroU64>,
    ) -> Result<(), SessionError> {
        self.require_active(now)?;
        if let Some(remaining) = self.remaining.as_mut() {
            let requested = requested.ok_or(SessionError::AuthorityWidened)?.get();
            *remaining = remaining
                .checked_sub(requested)
                .ok_or(SessionError::UsesExhausted)?;
        }
        Ok(())
    }

    pub(crate) fn record_activity(&mut self, now: Duration) -> Result<(), SessionError> {
        self.require_active(now)?;
        self.touch(now);
        Ok(())
    }

    fn require_active(&mut self, now: Duration) -> Result<(), SessionError> {
        if self.poll(now) == LeaseState::Active {
            Ok(())
        } else {
            Err(SessionError::NotActive)
        }
    }

    fn touch(&mut self, now: Duration) {
        self.idle_deadline = now
            .checked_add(self.limits.idle_timeout())
            .unwrap_or(self.hard_deadline)
            .min(self.hard_deadline);
    }

    pub(crate) fn stop(&mut self, reason: StopReason) {
        if self.state == LeaseState::Active {
            self.state = LeaseState::Stopping {
                reason,
                cleanup_failed: false,
            };
        }
    }

    pub(crate) fn shutdown(&mut self, now: Duration) {
        self.poll(now);
        self.stop(StopReason::NormalShutdown);
    }

    pub(crate) fn report_cleanup(&mut self, cleanup: Cleanup) -> Result<(), SessionError> {
        let LeaseState::Stopping {
            reason,
            cleanup_failed,
        } = self.state
        else {
            return Err(SessionError::InvalidTransition);
        };
        self.state = match cleanup {
            Cleanup::Complete => LeaseState::Terminated {
                reason,
                cleanup_failed,
            },
            Cleanup::Failed => LeaseState::Stopping {
                reason,
                cleanup_failed: true,
            },
        };
        Ok(())
    }
}
