use anyhow::{bail, Context, Result};
use dev_tools_secret::OperationContext;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) const PROVIDER_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const FINALIZATION_RESERVE: Duration = Duration::from_secs(2);
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

/// One admitted provider operation and its absolute execution budget.
///
/// In the strong broker the cancellation flag is owned by the admitted session
/// guard, so provider work cannot outlive that guard's cancellation authority.
/// Legacy nonbroker operations borrow a private never-cancelled flag but remain
/// bounded by the same absolute deadline.
#[derive(Debug)]
pub(crate) struct ProviderOperation<'a> {
    cancellation: &'a AtomicBool,
    deadline: Instant,
}

impl<'a> ProviderOperation<'a> {
    pub(crate) fn new(cancellation: &'a AtomicBool) -> Result<Self> {
        Self::with_timeout(cancellation, PROVIDER_OPERATION_TIMEOUT)
    }

    fn with_timeout(cancellation: &'a AtomicBool, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            bail!("provider operation timeout must be positive");
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("provider operation deadline overflowed")?;
        Ok(Self {
            cancellation,
            deadline,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_timeout(
        cancellation: &'a AtomicBool,
        timeout: Duration,
    ) -> Result<Self> {
        Self::with_timeout(cancellation, timeout)
    }

    pub(crate) fn checkpoint(&self) -> Result<()> {
        self.checkpoint_at(Instant::now())
    }

    pub(crate) fn http_timeout(&self) -> Result<Duration> {
        self.http_timeout_at(Instant::now())
    }

    pub(crate) fn secret_context(&self) -> OperationContext<'a> {
        OperationContext::new(self.deadline, self.cancellation)
    }

    fn checkpoint_at(&self, now: Instant) -> Result<()> {
        if self.cancellation.load(Ordering::Acquire) {
            bail!("provider operation was cancelled");
        }
        if self.deadline <= now {
            bail!("provider operation deadline elapsed");
        }
        Ok(())
    }

    fn remaining_with_reserve_at(&self, now: Instant) -> Result<Duration> {
        self.checkpoint_at(now)?;
        self.deadline
            .checked_duration_since(now)
            .and_then(|remaining| remaining.checked_sub(FINALIZATION_RESERVE))
            .filter(|remaining| !remaining.is_zero())
            .context("provider operation has insufficient time remaining")
    }

    fn http_timeout_at(&self, now: Instant) -> Result<Duration> {
        Ok(self.remaining_with_reserve_at(now)?.min(MAX_HTTP_TIMEOUT))
    }
}

impl ProviderOperation<'static> {
    pub(crate) fn uncancelled() -> Result<Self> {
        Self::new(&NEVER_CANCELLED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_absolute_deadline_is_shared_by_subprocess_and_http_stages() {
        let cancelled = AtomicBool::new(false);
        let start = Instant::now();
        let operation = ProviderOperation {
            cancellation: &cancelled,
            deadline: start + Duration::from_secs(50),
        };

        assert_eq!(
            operation.remaining_with_reserve_at(start).unwrap(),
            Duration::from_secs(48)
        );
        assert_eq!(
            operation
                .remaining_with_reserve_at(start + Duration::from_secs(20))
                .unwrap(),
            Duration::from_secs(28)
        );
        assert_eq!(
            operation
                .remaining_with_reserve_at(start + Duration::from_secs(48))
                .unwrap_err()
                .to_string(),
            "provider operation has insufficient time remaining"
        );
    }

    #[test]
    fn http_stage_is_capped_at_thirty_seconds_and_uses_the_same_reserve() {
        let cancelled = AtomicBool::new(false);
        let start = Instant::now();
        let operation = ProviderOperation {
            cancellation: &cancelled,
            deadline: start + Duration::from_secs(90),
        };

        assert_eq!(
            operation.http_timeout_at(start).unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            operation
                .http_timeout_at(start + Duration::from_secs(70))
                .unwrap(),
            Duration::from_secs(18)
        );
    }

    #[test]
    fn caller_cancellation_fails_every_subsequent_checkpoint() {
        let cancelled = AtomicBool::new(false);
        let operation =
            ProviderOperation::with_test_timeout(&cancelled, Duration::from_millis(50)).unwrap();
        operation.checkpoint().unwrap();

        cancelled.store(true, Ordering::Release);

        assert_eq!(
            operation.checkpoint().unwrap_err().to_string(),
            "provider operation was cancelled"
        );
        assert_eq!(
            operation
                .remaining_with_reserve_at(Instant::now())
                .unwrap_err()
                .to_string(),
            "provider operation was cancelled"
        );
        assert_eq!(
            operation.http_timeout().unwrap_err().to_string(),
            "provider operation was cancelled"
        );
    }

    #[test]
    fn zero_and_expired_deadlines_fail_without_sleeping() {
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            ProviderOperation::with_test_timeout(&cancelled, Duration::ZERO)
                .unwrap_err()
                .to_string(),
            "provider operation timeout must be positive"
        );

        let now = Instant::now();
        let operation = ProviderOperation {
            cancellation: &cancelled,
            deadline: now,
        };
        assert_eq!(
            operation.checkpoint_at(now).unwrap_err().to_string(),
            "provider operation deadline elapsed"
        );
    }
}
