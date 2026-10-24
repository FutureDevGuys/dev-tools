use dev_tools_privilege_session::{
    Cleanup, Constraint, GrantLimits, GrantRegistry, LeaseState, SessionError, StopReason,
};
use std::num::NonZeroU64;
use std::time::Duration;

#[derive(Clone, Debug)]
struct Scope(u32, Option<u64>);
impl Constraint for Scope {
    fn contains(&self, narrower: &Self) -> bool {
        self.0 == narrower.0 && (self.1.is_none() || self.1 == narrower.1)
    }
}
#[derive(Clone, Debug)]
struct Permission(u32);
impl Constraint for Permission {
    fn contains(&self, narrower: &Self) -> bool {
        self.0 & narrower.0 == narrower.0
    }
}
fn at(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}
fn limits(seconds: u64) -> GrantLimits {
    GrantLimits::from_administrator_policy(at(seconds), at(seconds)).unwrap()
}
fn count(value: u64) -> Option<NonZeroU64> {
    Some(NonZeroU64::new(value).unwrap())
}
fn registry() -> GrantRegistry<Scope, Permission> {
    let mut registry = GrantRegistry::new(8).unwrap();
    registry
        .issue(
            1,
            Scope(1000, None),
            Permission(0b111),
            limits(43200),
            count(10),
            at(0),
        )
        .unwrap();
    registry
}

#[test]
fn explicit_selection_checks_scope_and_never_falls_back_to_wider_authority() {
    let mut registry = registry();
    registry
        .issue(
            2,
            Scope(1000, Some(7)),
            Permission(1),
            limits(100),
            None,
            at(0),
        )
        .unwrap();
    assert_eq!(
        registry.admit(2, &Scope(1000, Some(8)), &Permission(1), at(1)),
        Err(SessionError::IdentityMismatch)
    );
    assert_eq!(
        registry.admit(2, &Scope(1000, Some(7)), &Permission(2), at(1)),
        Err(SessionError::AuthorityWidened)
    );
    assert_eq!(
        registry.admit(1, &Scope(1001, Some(7)), &Permission(1), at(1)),
        Err(SessionError::IdentityMismatch)
    );
    registry
        .admit(2, &Scope(1000, Some(7)), &Permission(1), at(99))
        .unwrap();
    assert_eq!(
        registry.admit(2, &Scope(1000, Some(7)), &Permission(1), at(100)),
        Err(SessionError::NotActive)
    );
    assert_eq!(
        registry.get(1).unwrap().lifetime.state(),
        LeaseState::Active
    );
}

#[test]
fn delegated_use_budgets_are_reserved_once_and_cannot_multiply() {
    let mut registry = registry();
    registry
        .delegate(
            1,
            &Scope(1000, None),
            2,
            Scope(1000, Some(7)),
            Permission(1),
            limits(300),
            count(7),
            at(1),
        )
        .unwrap();
    assert_eq!(registry.get(1).unwrap().lifetime.remaining_uses(), Some(3));
    assert_eq!(
        registry.delegate(
            1,
            &Scope(1000, None),
            3,
            Scope(1000, Some(8)),
            Permission(1),
            limits(300),
            count(4),
            at(1)
        ),
        Err(SessionError::UsesExhausted)
    );
    assert_eq!(
        registry.delegate(
            1,
            &Scope(1000, None),
            3,
            Scope(1000, None),
            Permission(1),
            limits(300),
            None,
            at(1)
        ),
        Err(SessionError::AuthorityWidened)
    );
    for second in 2..9 {
        registry
            .admit(2, &Scope(1000, Some(7)), &Permission(1), at(second))
            .unwrap();
    }
    assert_eq!(
        registry.admit(2, &Scope(1000, Some(7)), &Permission(1), at(10)),
        Err(SessionError::UsesExhausted)
    );
    assert_eq!(registry.get(1).unwrap().lifetime.remaining_uses(), Some(3));
}

#[test]
fn child_cannot_expand_identity_permissions_or_lifetime() {
    let mut registry = registry();
    registry
        .delegate(
            1,
            &Scope(1000, None),
            2,
            Scope(1000, Some(7)),
            Permission(1),
            limits(100),
            count(5),
            at(1),
        )
        .unwrap();
    for (scope, permission, duration) in [
        (Scope(1000, None), Permission(1), 50),
        (Scope(1000, Some(8)), Permission(1), 50),
        (Scope(1000, Some(7)), Permission(2), 50),
        (Scope(1000, Some(7)), Permission(1), 101),
    ] {
        assert_eq!(
            registry.delegate(
                2,
                &Scope(1000, Some(7)),
                3,
                scope,
                permission,
                limits(duration),
                count(1),
                at(2)
            ),
            Err(SessionError::AuthorityWidened)
        );
    }
    assert_eq!(registry.get(2).unwrap().lifetime.remaining_uses(), Some(5));
}

#[test]
fn revocation_is_recursive_and_requires_child_cleanup_before_parent_success() {
    let mut registry = registry();
    registry
        .delegate(
            1,
            &Scope(1000, None),
            2,
            Scope(1000, Some(7)),
            Permission(1),
            limits(300),
            count(5),
            at(1),
        )
        .unwrap();
    registry
        .delegate(
            2,
            &Scope(1000, Some(7)),
            3,
            Scope(1000, Some(7)),
            Permission(1),
            limits(100),
            count(2),
            at(2),
        )
        .unwrap();
    registry.stop(1, StopReason::Revoked, at(3)).unwrap();
    for id in [1, 2, 3] {
        assert_eq!(
            registry.admit(id, &Scope(1000, Some(7)), &Permission(1), at(3)),
            Err(SessionError::NotActive)
        );
    }
    assert_eq!(
        registry.report_cleanup(1, Cleanup::Complete),
        Err(SessionError::InvalidTransition)
    );
    registry.report_cleanup(3, Cleanup::Failed).unwrap();
    assert!(!registry.get(3).unwrap().lifetime.state().is_terminal());
    registry.report_cleanup(3, Cleanup::Complete).unwrap();
    registry.report_cleanup(2, Cleanup::Complete).unwrap();
    registry.report_cleanup(1, Cleanup::Complete).unwrap();
    assert_eq!(registry.retire(1), Err(SessionError::InvalidTransition));
    for id in [3, 2, 1] {
        registry.retire(id).unwrap();
    }
    assert_eq!(registry.iter().count(), 0);
}

#[test]
fn an_unlimited_use_count_still_has_a_finite_nonrenewable_deadline() {
    let mut registry = GrantRegistry::new(2).unwrap();
    registry
        .issue(
            1,
            Scope(1000, None),
            Permission(1),
            limits(43200),
            None,
            at(0),
        )
        .unwrap();
    registry
        .delegate(
            1,
            &Scope(1000, None),
            2,
            Scope(1000, Some(7)),
            Permission(1),
            limits(43199),
            None,
            at(1),
        )
        .unwrap();
    for time in [2, 1800, 36000, 43199] {
        registry
            .admit(2, &Scope(1000, Some(7)), &Permission(1), at(time))
            .unwrap();
    }
    assert_eq!(registry.get(2).unwrap().lifetime.remaining_uses(), None);
    assert_eq!(registry.get(1).unwrap().lifetime.hard_deadline(), at(43200));
    registry.poll(at(43200));
    assert!(registry
        .iter()
        .all(|grant| grant.lifetime.state() != LeaseState::Active));
}

fn idle_limits(idle: u64, hard: u64) -> GrantLimits {
    GrantLimits::from_administrator_policy(at(idle), at(hard)).unwrap()
}

fn idle_grant(registry: &mut GrantRegistry<Scope, Permission>, id: u128) {
    registry
        .issue(
            id,
            Scope(1000, None),
            Permission(1),
            idle_limits(10, 100),
            None,
            at(0),
        )
        .unwrap();
}

fn state(registry: &GrantRegistry<Scope, Permission>, id: u128) -> LeaseState {
    registry.get(id).unwrap().lifetime.state()
}

#[test]
fn a_grant_with_attached_work_is_not_idle_until_that_work_ends() {
    let mut registry = GrantRegistry::new(8).unwrap();
    idle_grant(&mut registry, 1);
    registry.attach(1).unwrap();
    assert_eq!(
        registry.get(1).unwrap().lifetime.next_deadline(),
        Some(at(100)),
        "only the hard deadline can end a grant that runs a job"
    );
    registry.poll(at(50));
    assert_eq!(state(&registry, 1), LeaseState::Active, "a running job");
    registry.detach(1, at(60)).unwrap();
    registry.poll(at(69));
    assert_eq!(
        state(&registry, 1),
        LeaseState::Active,
        "idleness counts from the end of the job"
    );
    registry.poll(at(70));
    assert!(matches!(
        state(&registry, 1),
        LeaseState::Stopping {
            reason: StopReason::IdleExpired,
            ..
        }
    ));
}

#[test]
fn attached_work_does_not_outlast_the_hard_deadline() {
    let mut registry = GrantRegistry::new(8).unwrap();
    idle_grant(&mut registry, 1);
    registry.attach(1).unwrap();
    registry.poll(at(100));
    assert!(matches!(
        state(&registry, 1),
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            ..
        }
    ));
}

#[test]
fn a_delegated_grants_attached_work_keeps_its_parent_from_idling() {
    let mut registry = GrantRegistry::new(8).unwrap();
    idle_grant(&mut registry, 1);
    registry
        .delegate(
            1,
            &Scope(1000, None),
            2,
            Scope(1000, Some(7)),
            Permission(1),
            idle_limits(10, 90),
            None,
            at(1),
        )
        .unwrap();
    registry.attach(2).unwrap();
    registry.poll(at(50));
    assert_eq!(state(&registry, 1), LeaseState::Active, "the parent");
    assert_eq!(
        state(&registry, 2),
        LeaseState::Active,
        "the delegated grant"
    );
}
