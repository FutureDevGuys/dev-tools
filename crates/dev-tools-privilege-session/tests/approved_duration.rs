use dev_tools_privilege_session::{
    LeaseLifecycle, LeaseLimits, LeaseState, SessionError, StopReason,
};
use std::num::NonZeroU64;
use std::time::Duration;

fn hours(value: u64) -> Duration {
    Duration::from_secs(value * 60 * 60)
}

#[test]
fn administrator_can_approve_twelve_hours_without_an_idle_cutoff() {
    let limits = LeaseLimits::from_administrator_policy(hours(12), hours(12))
        .expect("an explicitly permitted twelve-hour grant must not hit a product-wide cap");
    let mut lease =
        LeaseLifecycle::new(limits, Duration::ZERO, NonZeroU64::new(10).unwrap()).unwrap();
    assert_eq!(lease.poll(hours(11)), LeaseState::Active);
    lease.admit(hours(11)).unwrap();
    assert_eq!(lease.next_deadline(), Some(hours(12)));
    assert_eq!(lease.admit(hours(12)), Err(SessionError::NotActive));
    assert_eq!(
        lease.state(),
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            cleanup_failed: false,
        }
    );
    assert!(!lease.state().is_terminal());
}

#[test]
fn administrator_policy_can_authorize_an_overnight_duration() {
    let limits = LeaseLimits::from_administrator_policy(hours(12), hours(12))
        .expect("explicit overnight limits must not be rejected by a product-wide eight-hour cap");
    let mut lease =
        LeaseLifecycle::new(limits, Duration::ZERO, NonZeroU64::new(10).unwrap()).unwrap();
    assert_eq!(lease.poll(hours(8)), LeaseState::Active);
    lease.record_activity(hours(11)).unwrap();
    assert_eq!(lease.next_deadline(), Some(hours(12)));
    assert_eq!(
        lease.poll(hours(12)),
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            cleanup_failed: false,
        }
    );
    assert_eq!(lease.admit(hours(12)), Err(SessionError::NotActive));
    assert!(!lease.state().is_terminal());
}

#[test]
fn explicit_duration_can_narrow_but_not_widen_administrator_policy() {
    let policy = LeaseLimits::from_administrator_policy(hours(24), hours(24)).unwrap();
    let approved = LeaseLimits::for_approved_duration(policy, hours(12)).unwrap();
    assert_eq!(approved.idle_timeout(), hours(12));
    assert_eq!(approved.hard_timeout(), hours(12));
    for invalid in [Duration::ZERO, hours(25), Duration::MAX] {
        assert_eq!(
            LeaseLimits::for_approved_duration(policy, invalid),
            Err(SessionError::InvalidLimits)
        );
    }
    let policy = LeaseLimits::from_administrator_policy(hours(1), hours(24)).unwrap();
    assert_eq!(
        LeaseLimits::for_approved_duration(policy, hours(12))
            .unwrap()
            .idle_timeout(),
        hours(1)
    );
}

#[test]
fn frequent_accepted_activity_does_not_extend_a_shorter_approved_deadline() {
    let policy = LeaseLimits::from_administrator_policy(hours(24), hours(24)).unwrap();
    let approved = LeaseLimits::for_approved_duration(policy, hours(12)).unwrap();
    let mut lease = LeaseLifecycle::new(approved, hours(3), NonZeroU64::new(20).unwrap()).unwrap();
    for hour in 4..15 {
        lease.admit(hours(hour)).unwrap();
        assert_eq!(lease.next_deadline(), Some(hours(15)));
    }
    assert_eq!(lease.admit(hours(15)), Err(SessionError::NotActive));
    assert!(matches!(
        lease.state(),
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            ..
        }
    ));
}

#[test]
fn large_policy_duration_cannot_overflow_a_native_clock_deadline() {
    let limits = LeaseLimits::from_administrator_policy(Duration::MAX, Duration::MAX).unwrap();
    assert!(matches!(
        LeaseLifecycle::new(limits, hours(1), NonZeroU64::new(1).unwrap()),
        Err(SessionError::InvalidClock)
    ));
}
