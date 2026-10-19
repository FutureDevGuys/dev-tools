use dev_tools_privilege_session::{
    Cleanup, GrantLifecycle, GrantLimits, LeaseLifecycle, LeaseLimits, LeaseState, SessionError,
    StopReason, MAX_HARD_TIMEOUT,
};
use std::num::NonZeroU64;
use std::time::Duration;

#[test]
fn finite_facade_keeps_its_public_budget_and_duration_contract() {
    let mut lease = LeaseLifecycle::new(
        LeaseLimits::standard(),
        Duration::ZERO,
        NonZeroU64::new(1).unwrap(),
    )
    .unwrap();
    let before: u64 = lease.remaining_uses();
    assert_eq!(before, 1);
    lease.admit(Duration::from_secs(1)).unwrap();
    assert_eq!(lease.remaining_uses(), 0);
    assert_eq!(
        lease.admit(Duration::from_secs(2)),
        Err(SessionError::UsesExhausted)
    );
    assert_eq!(lease.state(), LeaseState::Active);
    lease.shutdown(Duration::from_secs(3));
    lease.report_cleanup(Cleanup::Complete).unwrap();
    assert!(lease.state().is_clean_shutdown());
    assert_eq!(
        LeaseLimits::from_administrator_policy(
            Duration::from_secs(1),
            MAX_HARD_TIMEOUT + Duration::from_secs(1),
        ),
        Err(SessionError::InvalidLimits)
    );
}

#[test]
fn grant_facade_supports_an_explicit_overnight_unlimited_budget() {
    let approved = Duration::from_secs(12 * 60 * 60);
    let policy = GrantLimits::from_administrator_policy(approved, approved).unwrap();
    let limits = GrantLimits::for_approved_duration(policy, approved).unwrap();
    let mut grant = GrantLifecycle::with_use_limit(limits, Duration::ZERO, None).unwrap();
    assert_eq!(grant.remaining_uses(), None);
    grant.admit(Duration::from_secs(1)).unwrap();
    assert_eq!(grant.hard_deadline(), approved);
    assert_eq!(
        grant.poll(approved),
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            cleanup_failed: false,
        }
    );
}

#[test]
fn finite_facades_have_identical_clock_and_cleanup_semantics() {
    let idle = Duration::from_secs(3);
    let hard = Duration::from_secs(10);
    let uses = NonZeroU64::new(2).unwrap();
    let mut lease = LeaseLifecycle::new(
        LeaseLimits::from_administrator_policy(idle, hard).unwrap(),
        Duration::ZERO,
        uses,
    )
    .unwrap();
    let mut grant = GrantLifecycle::new(
        GrantLimits::from_administrator_policy(idle, hard).unwrap(),
        Duration::ZERO,
        uses,
    )
    .unwrap();
    for time in [1, 2] {
        lease.admit(Duration::from_secs(time)).unwrap();
        grant.admit(Duration::from_secs(time)).unwrap();
        assert_eq!(Some(lease.remaining_uses()), grant.remaining_uses());
        assert_eq!(lease.next_deadline(), grant.next_deadline());
    }
    assert_eq!(
        lease.poll(Duration::from_secs(5)),
        grant.poll(Duration::from_secs(5))
    );
    for cleanup in [Cleanup::Failed, Cleanup::Complete] {
        lease.report_cleanup(cleanup).unwrap();
        grant.report_cleanup(cleanup).unwrap();
        assert_eq!(lease.state(), grant.state());
    }
}
