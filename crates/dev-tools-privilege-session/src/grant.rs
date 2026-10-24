//! Explicit finite-duration grant accounting with an optional use budget.
//!
//! Administrator policy and native approval remain product-owned. This facade
//! cannot be converted into the finite maintenance facade or authorize execution.

use crate::lifecycle::LifecycleCore;
use crate::{Cleanup, LeaseLimits, LeaseState, SessionError, StopReason};
use std::num::NonZeroU64;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantLimits {
    idle: Duration,
    hard: Duration,
}

impl GrantLimits {
    pub const fn standard() -> Self {
        Self {
            idle: crate::DEFAULT_IDLE_TIMEOUT,
            hard: crate::DEFAULT_HARD_TIMEOUT,
        }
    }

    /// Validate trusted policy limits without a product-wide duration cap.
    pub fn from_administrator_policy(idle: Duration, hard: Duration) -> Result<Self, SessionError> {
        if idle.is_zero() || hard.is_zero() || idle > hard {
            return Err(SessionError::InvalidLimits);
        }
        Ok(Self { idle, hard })
    }

    /// Narrow an approved duration within the policy's idle and hard ceilings.
    /// Equal idle/hard values represent a grant with no shorter idle cutoff.
    pub fn for_approved_duration(
        policy: Self,
        approved_duration: Duration,
    ) -> Result<Self, SessionError> {
        if approved_duration.is_zero() || approved_duration > policy.hard {
            return Err(SessionError::InvalidLimits);
        }
        Ok(Self {
            idle: policy.idle.min(approved_duration),
            hard: approved_duration,
        })
    }

    pub const fn idle_timeout(self) -> Duration {
        self.idle
    }

    pub const fn hard_timeout(self) -> Duration {
        self.hard
    }

    pub(crate) const fn from_fixed(limits: LeaseLimits) -> Self {
        Self {
            idle: limits.idle_timeout(),
            hard: limits.hard_timeout(),
        }
    }
}

/// One non-cloneable owner; inspection cannot extend the immutable hard deadline.
pub struct GrantLifecycle {
    core: LifecycleCore,
}

impl GrantLifecycle {
    pub fn new(limits: GrantLimits, now: Duration, uses: NonZeroU64) -> Result<Self, SessionError> {
        Self::with_use_limit(limits, now, Some(uses))
    }

    /// An unlimited use budget is explicit; a finite approved duration still applies.
    pub fn with_use_limit(
        limits: GrantLimits,
        now: Duration,
        uses: Option<NonZeroU64>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            core: LifecycleCore::new(limits, now, uses)?,
        })
    }

    pub const fn state(&self) -> LeaseState {
        self.core.state()
    }

    pub const fn remaining_uses(&self) -> Option<u64> {
        self.core.remaining_uses()
    }

    pub const fn hard_deadline(&self) -> Duration {
        self.core.hard_deadline()
    }

    pub const fn limits(&self) -> GrantLimits {
        self.core.limits()
    }

    pub fn next_deadline(&self) -> Option<Duration> {
        self.core.next_deadline()
    }

    pub fn poll(&mut self, now: Duration) -> LeaseState {
        self.core.poll(now)
    }

    pub fn admit(&mut self, now: Duration) -> Result<(), SessionError> {
        self.core.admit(now)
    }

    pub(crate) fn reserve_uses(
        &mut self,
        now: Duration,
        requested: Option<NonZeroU64>,
    ) -> Result<(), SessionError> {
        self.core.reserve_uses(now, requested)
    }

    pub fn record_activity(&mut self, now: Duration) -> Result<(), SessionError> {
        self.core.record_activity(now)
    }

    pub(crate) fn attach(&mut self) -> Result<(), SessionError> {
        self.core.attach()
    }

    pub(crate) fn detach(&mut self, now: Duration) -> Result<(), SessionError> {
        self.core.detach(now)
    }

    pub fn stop(&mut self, reason: StopReason) {
        self.core.stop(reason);
    }

    pub fn report_cleanup(&mut self, cleanup: Cleanup) -> Result<(), SessionError> {
        self.core.report_cleanup(cleanup)
    }
}
