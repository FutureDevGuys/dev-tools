//! Product-neutral lease lifecycle, not native authorization or containment.
//!
//! A trusted coordinator owns this value and supplies observations from one
//! native monotonic clock whose suspend behavior meets its platform contract.
//! Caller-provided timestamps, serialized lease IDs, and this state machine are
//! never proof of native identity or permission. The coordinator must authenticate
//! each operation, conserve delegated authority, and retain the native process
//! boundary until cleanup is positively observed.
//!
//! This first foundation implements local lifecycle only. It starts no process,
//! thread, timer, privileged helper, or network request. Native backends and
//! authority delegation are not implemented or advertised as accepted.

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_HARD_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
pub const MAX_HARD_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseLimits {
    idle: Duration,
    hard: Duration,
}

impl LeaseLimits {
    pub const fn standard() -> Self {
        Self {
            idle: DEFAULT_IDLE_TIMEOUT,
            hard: DEFAULT_HARD_TIMEOUT,
        }
    }

    /// Validates limits selected by trusted administrator policy. This does not
    /// authorize a request to raise the standard limits.
    pub fn from_administrator_policy(idle: Duration, hard: Duration) -> Result<Self, SessionError> {
        if idle.is_zero() || hard.is_zero() || idle > hard || hard > MAX_HARD_TIMEOUT {
            return Err(SessionError::InvalidLimits);
        }
        Ok(Self { idle, hard })
    }

    pub const fn idle_timeout(self) -> Duration {
        self.idle
    }
    pub const fn hard_timeout(self) -> Duration {
        self.hard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopReason {
    IdleExpired,
    HardExpired,
    ClockRegressed,
    Revoked,
    ParentRevoked,
    AuthorityChanged,
    BrokerShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleanup {
    Complete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseState {
    Active,
    Stopping {
        reason: StopReason,
        cleanup_failed: bool,
    },
    Terminated {
        reason: StopReason,
        cleanup_failed: bool,
    },
}

impl LeaseState {
    /// Only positive native cleanup evidence can establish terminal state.
    /// A terminal state may still retain a prior cleanup failure.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated { .. })
    }
}

/// One coordinator owns all mutations; there is no cloning or serialization of
/// the live use budget. Read-only status snapshots do not refresh idle expiry.
///
/// ```compile_fail
/// use dev_tools_privilege_session::{LeaseLifecycle, LeaseLimits};
/// use std::{num::NonZeroU64, time::Duration};
/// let lease = LeaseLifecycle::new(LeaseLimits::standard(), Duration::ZERO,
///     NonZeroU64::new(1).unwrap()).unwrap();
/// let duplicate_budget = lease.clone();
/// ```
pub struct LeaseLifecycle {
    limits: LeaseLimits,
    hard_deadline: Duration,
    idle_deadline: Duration,
    last_observed: Duration,
    remaining: u64,
    state: LeaseState,
}

impl LeaseLifecycle {
    pub fn new(limits: LeaseLimits, now: Duration, uses: NonZeroU64) -> Result<Self, SessionError> {
        let hard_deadline = now
            .checked_add(limits.hard)
            .ok_or(SessionError::InvalidClock)?;
        let idle_deadline = now
            .checked_add(limits.idle)
            .ok_or(SessionError::InvalidClock)?;
        Ok(Self {
            limits,
            hard_deadline,
            idle_deadline,
            last_observed: now,
            remaining: uses.get(),
            state: LeaseState::Active,
        })
    }

    pub const fn state(&self) -> LeaseState {
        self.state
    }
    pub const fn remaining_uses(&self) -> u64 {
        self.remaining
    }

    /// The coordinator schedules a native expiry check at this deadline. Merely
    /// owning the lifecycle value installs no timer and stops no process.
    pub fn next_deadline(&self) -> Option<Duration> {
        (self.state == LeaseState::Active).then(|| self.hard_deadline.min(self.idle_deadline))
    }

    /// Observe time without accepted activity. Hard expiry wins over idle expiry
    /// when both are observed together; the first stopping cause is retained.
    pub fn poll(&mut self, now: Duration) -> LeaseState {
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

    /// Consume one use only after the coordinator validates native identity,
    /// audience, scope, and exact operation. Failed spawn does not refund it.
    /// Exhaustion denies new work but does not cancel the last accepted operation.
    pub fn admit(&mut self, now: Duration) -> Result<(), SessionError> {
        self.require_active(now)?;
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(SessionError::UsesExhausted)?;
        self.touch(now);
        Ok(())
    }

    /// The trusted coordinator reports useful activity from already-admitted
    /// work. Status, heartbeat, and untrusted client traffic must not call this.
    pub fn record_activity(&mut self, now: Duration) -> Result<(), SessionError> {
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
        // An unrepresentable idle deadline lies beyond the already validated
        // hard deadline; clamp rather than wrap or extend the lease.
        self.idle_deadline = now
            .checked_add(self.limits.idle)
            .unwrap_or(self.hard_deadline)
            .min(self.hard_deadline);
    }

    /// Deny admission immediately. The coordinator must then cancel and join the
    /// retained native boundary; this transition alone is not revocation success.
    pub fn stop(&mut self, reason: StopReason) {
        if self.state == LeaseState::Active {
            self.state = LeaseState::Stopping {
                reason,
                cleanup_failed: false,
            };
        }
    }

    /// Reports positive cleanup evidence, not a signal-send or leader-exit event.
    /// Failed cleanup stays nonterminal. A successful retry retains its failure
    /// history so callers cannot silently report the original operation successful.
    pub fn report_cleanup(&mut self, cleanup: Cleanup) -> Result<(), SessionError> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    InvalidLimits,
    InvalidClock,
    NotActive,
    UsesExhausted,
    InvalidTransition,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "administrator lease limits are invalid",
            Self::InvalidClock => "administrator lease deadline is not representable",
            Self::NotActive => "administrator lease is not active",
            Self::UsesExhausted => "administrator lease use budget is exhausted",
            Self::InvalidTransition => "administrator lease transition is invalid",
        })
    }
}

impl std::error::Error for SessionError {}
