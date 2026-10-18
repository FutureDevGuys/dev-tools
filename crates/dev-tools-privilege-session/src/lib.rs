//! Product-neutral lease lifecycle, not native authorization or containment.
//!
//! A trusted coordinator owns this value and supplies observations from one
//! native monotonic clock whose suspend behavior meets its platform contract.
//! Caller-provided timestamps, serialized lease IDs, and this state machine are
//! never proof of native identity or permission. The coordinator must authenticate
//! each operation, conserve delegated authority, and retain the native process
//! boundary until cleanup is positively observed.
//!
//! This foundation implements local lifecycle and reusable admission accounting.
//! Lifecycle/accounting values start no process, timer or authority. The explicit
//! Linux module supplies held cgroup, peer and gated-process mechanics only.
//! Product authorization, independent guardians, sandbox policy and complete
//! native acceptance remain separate requirements. Registry delegation conserves
//! accounting only; products still own native delegated authority.

mod authority;
pub use authority::*;
mod grant;
mod lifecycle;
pub use grant::{GrantLifecycle, GrantLimits};
mod registry;
pub use registry::{Constraint, GrantId, GrantRegistry, GrantView};

#[cfg(target_os = "linux")]
pub mod linux;

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
        if hard > MAX_HARD_TIMEOUT {
            return Err(SessionError::InvalidLimits);
        }
        GrantLimits::from_administrator_policy(idle, hard)?;
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
    WorkloadEnded,
    Logout,
    /// Explicit normal completion, still requiring positive native cleanup.
    NormalShutdown,
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

    /// Normal shutdown is successful only after positive cleanup with no prior
    /// cleanup failure. Revocation and expiry are distinct terminal outcomes.
    pub const fn is_clean_shutdown(self) -> bool {
        matches!(
            self,
            Self::Terminated {
                reason: StopReason::NormalShutdown,
                cleanup_failed: false
            }
        )
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
    core: lifecycle::LifecycleCore,
}

impl LeaseLifecycle {
    pub fn new(limits: LeaseLimits, now: Duration, uses: NonZeroU64) -> Result<Self, SessionError> {
        Ok(Self {
            core: lifecycle::LifecycleCore::new(GrantLimits::from_fixed(limits), now, Some(uses))?,
        })
    }

    pub const fn state(&self) -> LeaseState {
        self.core.state()
    }

    /// This facade always has a finite budget, preserving the existing API.
    pub const fn remaining_uses(&self) -> u64 {
        match self.core.remaining_uses() {
            Some(remaining) => remaining,
            None => panic!("fixed lease facade always constructs a finite budget"),
        }
    }

    /// Merely owning a lifecycle installs no timer and stops no process.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.core.next_deadline()
    }

    pub fn poll(&mut self, now: Duration) -> LeaseState {
        self.core.poll(now)
    }

    /// Failed spawn does not refund an admitted use.
    pub fn admit(&mut self, now: Duration) -> Result<(), SessionError> {
        self.core.admit(now)
    }

    /// Only already-admitted useful activity may reset idle expiry.
    pub fn record_activity(&mut self, now: Duration) -> Result<(), SessionError> {
        self.core.record_activity(now)
    }

    pub fn stop(&mut self, reason: StopReason) {
        self.core.stop(reason);
    }

    /// Close admission for normal completion without skipping native cleanup.
    pub fn shutdown(&mut self, now: Duration) {
        self.core.shutdown(now);
    }

    /// Failed cleanup stays nonterminal and successful retry retains failure history.
    pub fn report_cleanup(&mut self, cleanup: Cleanup) -> Result<(), SessionError> {
        self.core.report_cleanup(cleanup)
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
    UnknownGrant,
    DuplicateGrant,
    Capacity,
    AuthorityWidened,
    IdentityMismatch,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "administrator lease limits are invalid",
            Self::InvalidClock => "administrator lease deadline is not representable",
            Self::NotActive => "administrator lease is not active",
            Self::UsesExhausted => "administrator lease use budget is exhausted",
            Self::InvalidTransition => "administrator lease transition is invalid",
            Self::UnknownGrant => "administrator grant is unknown",
            Self::DuplicateGrant => "administrator grant identity already exists",
            Self::Capacity => "administrator grant registry is at capacity",
            Self::AuthorityWidened => "administrator grant would widen approved authority",
            Self::IdentityMismatch => "native caller is outside the administrator grant",
        })
    }
}

impl std::error::Error for SessionError {}

#[cfg(target_os = "linux")]
pub mod native_linux;
