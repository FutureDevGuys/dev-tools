use dev_tools_privilege_session::{
    Cleanup, LeaseLifecycle, LeaseLimits, LeaseState, SessionError, StopReason,
};
use std::num::NonZeroU64;
use std::time::Duration;

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn lease() -> LeaseLifecycle {
    LeaseLifecycle::new(
        LeaseLimits::standard(),
        seconds(10),
        NonZeroU64::new(5).unwrap(),
    )
    .unwrap()
}

#[test]
fn standard_limits_and_policy_bounds_are_explicit() {
    let standard = LeaseLimits::standard();
    assert_eq!(standard.idle_timeout(), seconds(1800));
    assert_eq!(standard.hard_timeout(), seconds(7200));
    assert!(LeaseLimits::from_administrator_policy(seconds(1800), seconds(28800)).is_ok());
    for (idle, hard) in [(0, 1), (1, 0), (2, 1), (1, 28801)] {
        assert_eq!(
            LeaseLimits::from_administrator_policy(seconds(idle), seconds(hard)),
            Err(SessionError::InvalidLimits)
        );
    }
}

#[test]
fn polling_never_keeps_a_lease_alive_and_expiry_requires_cleanup() {
    let mut lease = lease();
    assert_eq!(lease.poll(seconds(1809)), LeaseState::Active);
    assert_eq!(
        lease.poll(seconds(1810)),
        LeaseState::Stopping {
            reason: StopReason::IdleExpired,
            cleanup_failed: false
        }
    );
    assert_eq!(lease.admit(seconds(1810)), Err(SessionError::NotActive));
    assert!(!lease.state().is_terminal());
    lease.report_cleanup(Cleanup::Complete).unwrap();
    assert!(lease.state().is_terminal());
}

#[test]
fn useful_activity_resets_idle_but_never_hard_expiry() {
    let mut lease = lease();
    for time in [1800, 3500, 5200, 6900] {
        lease.record_activity(seconds(time)).unwrap();
    }
    assert_eq!(lease.next_deadline(), Some(seconds(7210)));
    assert_eq!(
        lease.poll(seconds(7210)),
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            cleanup_failed: false
        }
    );
    assert_eq!(
        lease.record_activity(seconds(7211)),
        Err(SessionError::NotActive)
    );
}

#[test]
fn a_clock_regression_fails_closed_instead_of_extending_authority() {
    let mut lease = lease();
    lease.poll(seconds(20));
    assert_eq!(
        lease.poll(seconds(19)),
        LeaseState::Stopping {
            reason: StopReason::ClockRegressed,
            cleanup_failed: false
        }
    );
    assert_eq!(lease.admit(seconds(21)), Err(SessionError::NotActive));
}

#[test]
fn use_exhaustion_does_not_cancel_the_last_approved_operation() {
    let mut lease = LeaseLifecycle::new(
        LeaseLimits::standard(),
        seconds(0),
        NonZeroU64::new(1).unwrap(),
    )
    .unwrap();
    lease.admit(seconds(1)).unwrap();
    assert_eq!(lease.remaining_uses(), 0);
    assert_eq!(lease.admit(seconds(2)), Err(SessionError::UsesExhausted));
    assert_eq!(lease.state(), LeaseState::Active);
    assert_eq!(lease.next_deadline(), Some(seconds(1801)));
}

#[test]
fn revocation_is_irreversible_and_cleanup_failure_is_not_terminal_success() {
    let mut lease = lease();
    lease.stop(StopReason::Revoked);
    lease.report_cleanup(Cleanup::Failed).unwrap();
    assert_eq!(
        lease.state(),
        LeaseState::Stopping {
            reason: StopReason::Revoked,
            cleanup_failed: true
        }
    );
    assert!(!lease.state().is_terminal());
    lease.stop(StopReason::AuthorityChanged);
    lease.report_cleanup(Cleanup::Complete).unwrap();
    assert_eq!(
        lease.state(),
        LeaseState::Terminated {
            reason: StopReason::Revoked,
            cleanup_failed: true
        }
    );
    assert_eq!(lease.admit(seconds(11)), Err(SessionError::NotActive));
    assert_eq!(
        lease.report_cleanup(Cleanup::Complete),
        Err(SessionError::InvalidTransition)
    );
}

#[test]
fn cleanup_cannot_be_reported_for_an_active_lease() {
    assert_eq!(
        lease().report_cleanup(Cleanup::Complete),
        Err(SessionError::InvalidTransition)
    );
}

#[test]
fn unrepresentable_deadlines_reject_before_admission() {
    assert!(matches!(
        LeaseLifecycle::new(
            LeaseLimits::standard(),
            Duration::MAX,
            NonZeroU64::new(1).unwrap()
        ),
        Err(SessionError::InvalidClock)
    ));
}
