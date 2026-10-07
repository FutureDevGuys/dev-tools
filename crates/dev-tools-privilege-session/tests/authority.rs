//! Synthetic state-machine evidence only: no native identity, approval, timer,
//! process containment, or privilege enforcement is established by this suite.

use dev_tools_privilege_session::*;
use std::cell::Cell;
use std::num::NonZeroU64;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}
fn uses(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}
fn id(value: u8) -> RequestId {
    RequestId::from_bytes([value; 32])
}
fn scope(values: &[u8]) -> ResourceScope {
    ResourceScope::new(
        values
            .iter()
            .map(|value| ResourceId::from_bytes([*value; 32])),
    )
    .unwrap()
}
fn binding() -> AuthorityBinding {
    AuthorityBinding::new(
        SessionId::from_bytes([1; 32]),
        AudienceId::from_bytes([2; 32]),
        PolicyIdentity::from_bytes([3; 32]),
        InstallationIdentity::from_bytes([4; 32]),
    )
}
fn typed(value: u8) -> OperationTarget {
    OperationTarget::Typed {
        operation: OperationId::from_bytes([value; 32]),
        definition: DefinitionDigest::from_bytes([10; 32]),
    }
}
fn plan() -> OperationTarget {
    OperationTarget::ExactPlan {
        plan: PlanId::from_bytes([1; 32]),
        digest: PlanDigest::from_bytes([20; 32]),
    }
}
fn operation(target: OperationTarget) -> OperationBinding {
    OperationBinding::new(target, HelperIdentity::from_bytes([7; 32]), scope(&[1, 2]))
}
fn request(number: u8, target: OperationTarget) -> OperationRequest {
    OperationRequest::new(
        id(number),
        binding(),
        operation(target),
        match target {
            OperationTarget::Typed { .. } => {
                OperationPayload::Typed(PayloadDigest::from_bytes([9; 32]))
            }
            OperationTarget::ExactPlan { .. } => OperationPayload::ExactPlan,
        },
    )
}
struct NativeHandleFixture {
    live: Cell<bool>,
}
fn session(total: u64) -> SessionAuthority<NativeHandleFixture> {
    SessionAuthority::new(
        binding(),
        RetainedCaller::new(NativeHandleFixture {
            live: Cell::new(true),
        }),
        LeaseLimits::from_administrator_policy(seconds(10), seconds(100)).unwrap(),
        Duration::ZERO,
        uses(total),
        vec![
            OperationGrant::new(operation(typed(1)), uses(2)),
            OperationGrant::new(operation(typed(2)), uses(3)),
            OperationGrant::new(operation(plan()), uses(2)),
        ],
    )
    .unwrap()
}
fn admit(
    authority: &mut SessionAuthority<NativeHandleFixture>,
    time: u64,
    number: u8,
    target: OperationTarget,
) -> Result<RequestId, AuthorityError> {
    authority.admit_checked(
        || seconds(time),
        request(number, target),
        |caller, _, _| caller.handle().live.get(),
    )
}
fn release(
    authority: &mut SessionAuthority<NativeHandleFixture>,
    time: u64,
    number: u8,
) -> Result<(), ReleaseError<&'static str>> {
    authority.release_checked(
        || seconds(time),
        id(number),
        |caller, _, _| caller.handle().live.get(),
        |_| Ok(()),
    )
}
fn run(
    authority: &mut SessionAuthority<NativeHandleFixture>,
    time: u64,
    number: u8,
    target: OperationTarget,
) {
    admit(authority, time, number, target).unwrap();
    release(authority, time, number).unwrap();
    assert_eq!(
        authority.complete_operation(seconds(time), id(number)),
        Ok(LeaseState::Active)
    );
}

#[test]
fn two_distinct_transactions_and_later_repeat_use_one_reusable_grant() {
    let mut authority = session(5);
    run(&mut authority, 1, 1, typed(1));
    run(&mut authority, 5, 2, typed(2));
    run(&mut authority, 10, 3, typed(1));
    assert_eq!(authority.status().state, LeaseState::Active);
    assert_eq!(authority.status().remaining_uses, 2);
    assert_eq!(authority.remaining_operation_uses(typed(1)), Some(0));
    assert_eq!(authority.remaining_operation_uses(typed(2)), Some(2));
    assert_eq!(authority.status().next_deadline, Some(seconds(20)));
    assert_eq!(authority.status().in_flight, None);
}

#[test]
fn exact_plan_is_reusable_without_replacing_any_bound_fields() {
    let mut authority = session(3);
    run(&mut authority, 1, 1, plan());
    run(&mut authority, 2, 2, plan());
    assert_eq!(
        admit(&mut authority, 3, 3, plan()),
        Err(AuthorityError::OperationUsesExhausted)
    );
    assert_eq!(authority.status().remaining_uses, 1);
}

#[test]
fn changed_session_audience_policy_and_installation_are_denied_before_validation() {
    for changed in [
        AuthorityBinding::new(
            SessionId::from_bytes([9; 32]),
            binding().audience(),
            binding().policy(),
            binding().installation(),
        ),
        AuthorityBinding::new(
            binding().session(),
            AudienceId::from_bytes([9; 32]),
            binding().policy(),
            binding().installation(),
        ),
        AuthorityBinding::new(
            binding().session(),
            binding().audience(),
            PolicyIdentity::from_bytes([9; 32]),
            binding().installation(),
        ),
        AuthorityBinding::new(
            binding().session(),
            binding().audience(),
            binding().policy(),
            InstallationIdentity::from_bytes([9; 32]),
        ),
    ] {
        let mut authority = session(5);
        let before = authority.status();
        let request = OperationRequest::new(
            id(1),
            changed,
            operation(typed(1)),
            OperationPayload::Typed(PayloadDigest::from_bytes([1; 32])),
        );
        assert_eq!(
            authority.admit_checked(
                || seconds(1),
                request,
                |_, _, _| panic!("binding check must precede validation")
            ),
            Err(AuthorityError::BindingMismatch)
        );
        assert_eq!(authority.status(), before);
    }
}

#[test]
fn unknown_operation_or_confused_typed_exact_plan_audience_is_denied() {
    let mut authority = session(5);
    assert_eq!(
        admit(&mut authority, 1, 1, typed(3)),
        Err(AuthorityError::OperationNotGranted)
    );
    let confused = OperationTarget::ExactPlan {
        plan: PlanId::from_bytes([2; 32]),
        digest: PlanDigest::from_bytes([10; 32]),
    };
    assert_eq!(
        admit(&mut authority, 1, 2, confused),
        Err(AuthorityError::OperationNotGranted)
    );
    assert_eq!(authority.status().remaining_uses, 5);
}

#[test]
fn changed_definition_plan_digest_or_helper_is_denied_before_consumption() {
    for (target, helper) in [
        (
            OperationTarget::Typed {
                operation: OperationId::from_bytes([1; 32]),
                definition: DefinitionDigest::from_bytes([99; 32]),
            },
            HelperIdentity::from_bytes([7; 32]),
        ),
        (
            OperationTarget::ExactPlan {
                plan: PlanId::from_bytes([1; 32]),
                digest: PlanDigest::from_bytes([99; 32]),
            },
            HelperIdentity::from_bytes([7; 32]),
        ),
        (typed(1), HelperIdentity::from_bytes([99; 32])),
    ] {
        let mut authority = session(5);
        let payload = match target {
            OperationTarget::Typed { .. } => {
                OperationPayload::Typed(PayloadDigest::from_bytes([1; 32]))
            }
            _ => OperationPayload::ExactPlan,
        };
        let request = OperationRequest::new(
            id(1),
            binding(),
            OperationBinding::new(target, helper, scope(&[1, 2])),
            payload,
        );
        assert_eq!(
            authority.admit_checked(|| seconds(1), request, |_, _, _| true),
            Err(AuthorityError::OperationMismatch)
        );
        assert_eq!(authority.status().remaining_uses, 5);
    }
}

#[test]
fn typed_resource_scope_can_only_narrow_and_exact_plan_scope_cannot_change() {
    for (target, resources, expected) in [
        (typed(1), scope(&[1]), Ok(id(1))),
        (typed(1), scope(&[]), Ok(id(1))),
        (
            typed(1),
            scope(&[1, 3]),
            Err(AuthorityError::ResourcesOutsideGrant),
        ),
        (
            plan(),
            scope(&[1]),
            Err(AuthorityError::ResourcesOutsideGrant),
        ),
        (
            plan(),
            scope(&[1, 2, 3]),
            Err(AuthorityError::ResourcesOutsideGrant),
        ),
    ] {
        let mut authority = session(5);
        let base = request(1, target);
        let narrowed = OperationRequest::new(
            base.id(),
            base.authority(),
            OperationBinding::new(target, base.operation().helper(), resources),
            base.payload(),
        );
        assert_eq!(
            authority.admit_checked(|| seconds(1), narrowed, |_, _, _| true),
            expected
        );
    }
}

#[test]
fn mismatched_payload_kind_cannot_smuggle_inputs_into_an_exact_plan() {
    for (target, payload) in [
        (typed(1), OperationPayload::ExactPlan),
        (
            plan(),
            OperationPayload::Typed(PayloadDigest::from_bytes([1; 32])),
        ),
    ] {
        let mut authority = session(5);
        let request = OperationRequest::new(id(1), binding(), operation(target), payload);
        assert_eq!(
            authority.admit_checked(|| seconds(1), request, |_, _, _| true),
            Err(AuthorityError::InvalidPayload)
        );
        assert_eq!(authority.status().remaining_uses, 5);
    }
}

#[test]
fn rejected_native_validation_consumes_nothing_and_does_not_refresh_idle() {
    let mut authority = session(5);
    authority.caller().handle().live.set(false);
    assert_eq!(
        admit(&mut authority, 9, 1, typed(1)),
        Err(AuthorityError::ValidationRejected)
    );
    assert_eq!(authority.status().remaining_uses, 5);
    assert_eq!(authority.status().next_deadline, Some(seconds(10)));
    authority.caller().handle().live.set(true);
    admit(&mut authority, 9, 1, typed(1)).unwrap();
    assert_eq!(authority.status().remaining_uses, 4);
}

#[test]
fn native_validation_cannot_age_admission_past_the_absolute_deadline() {
    let mut authority = session(5);
    let mut times = [seconds(9), seconds(10)].into_iter();
    assert_eq!(
        authority.admit_checked(
            || times.next().unwrap(),
            request(1, typed(1)),
            |_, _, _| true
        ),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    assert_eq!(authority.status().remaining_uses, 5);
    assert_eq!(authority.status().in_flight, None);
    assert!(matches!(
        authority.status().state,
        LeaseState::Stopping {
            reason: StopReason::IdleExpired,
            ..
        }
    ));
}

#[test]
fn one_in_flight_returns_busy_without_spending_or_extending_idle() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    let before = authority.status();
    assert_eq!(
        admit(&mut authority, 9, 2, typed(2)),
        Err(AuthorityError::Busy)
    );
    assert_eq!(authority.status(), before);
    release(&mut authority, 9, 1).unwrap();
    authority.complete_operation(seconds(9), id(1)).unwrap();
    admit(&mut authority, 10, 2, typed(2)).unwrap();
}

#[test]
fn replay_denial_survives_completion_and_changed_operation_or_payload() {
    let mut authority = session(5);
    run(&mut authority, 1, 1, typed(1));
    for target in [typed(1), typed(2), plan()] {
        assert_eq!(
            admit(&mut authority, 2, 1, target),
            Err(AuthorityError::Replay)
        );
    }
    let changed = OperationRequest::new(
        id(1),
        binding(),
        operation(typed(1)),
        OperationPayload::Typed(PayloadDigest::from_bytes([77; 32])),
    );
    assert_eq!(
        authority.admit_checked(|| seconds(2), changed, |_, _, _| true),
        Err(AuthorityError::Replay)
    );
    assert_eq!(authority.status().remaining_uses, 4);
}

#[test]
fn shared_and_per_operation_budgets_are_both_conserved() {
    let mut authority = session(3);
    run(&mut authority, 1, 1, typed(1));
    run(&mut authority, 2, 2, typed(1));
    assert_eq!(
        admit(&mut authority, 3, 3, typed(1)),
        Err(AuthorityError::OperationUsesExhausted)
    );
    run(&mut authority, 3, 3, typed(2));
    assert_eq!(
        admit(&mut authority, 4, 4, plan()),
        Err(AuthorityError::Lease(SessionError::UsesExhausted))
    );
    assert_eq!(authority.remaining_operation_uses(plan()), Some(2));
    assert_eq!(authority.remaining_operation_uses(typed(2)), Some(2));
    assert_eq!(authority.status().state, LeaseState::Active);
}

#[test]
fn last_admitted_operation_can_still_release_and_complete_after_use_exhaustion() {
    let mut authority = session(1);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    assert_eq!(authority.status().remaining_uses, 0);
    release(&mut authority, 2, 1).unwrap();
    authority.record_progress(seconds(3), id(1)).unwrap();
    assert_eq!(
        authority.complete_operation(seconds(4), id(1)),
        Ok(LeaseState::Active)
    );
}

#[test]
fn failed_gate_is_never_refunded_or_retried_and_needs_positive_completion() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    assert_eq!(
        authority.release_checked(
            || seconds(2),
            id(1),
            |_, _, _| true,
            |_| Err::<(), _>("uncertain mutation")
        ),
        Err(ReleaseError::Gate("uncertain mutation"))
    );
    assert_eq!(authority.status().remaining_uses, 4);
    assert_eq!(authority.remaining_operation_uses(typed(1)), Some(1));
    assert_eq!(
        authority.status().in_flight,
        Some((id(1), OperationPhase::ReleaseFailed))
    );
    assert_eq!(
        release(&mut authority, 3, 1),
        Err(ReleaseError::Authority(AuthorityError::AlreadyReleased))
    );
    assert_eq!(
        admit(&mut authority, 3, 2, typed(2)),
        Err(AuthorityError::Busy)
    );
    assert_eq!(
        authority.record_progress(seconds(3), id(1)),
        Err(AuthorityError::ProgressNotRunning)
    );
    authority.complete_operation(seconds(3), id(1)).unwrap();
    assert_eq!(authority.status().next_deadline, Some(seconds(11)));
    assert_eq!(
        admit(&mut authority, 4, 1, typed(1)),
        Err(AuthorityError::Replay)
    );
    admit(&mut authority, 4, 2, typed(2)).unwrap();
}

#[test]
fn panic_in_gate_does_not_restore_gate_or_budget() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), ReleaseError<()>> = authority.release_checked(
            || seconds(2),
            id(1),
            |_, _, _| true,
            |_| panic!("synthetic gate panic"),
        );
    }));
    assert!(panic.is_err());
    assert_eq!(
        authority.status().in_flight,
        Some((id(1), OperationPhase::ReleaseFailed))
    );
    assert_eq!(authority.status().remaining_uses, 4);
    assert_eq!(
        release(&mut authority, 3, 1),
        Err(ReleaseError::Authority(AuthorityError::AlreadyReleased))
    );
}

#[test]
fn delayed_gate_rechecks_idle_hard_and_clock_regression_before_effects() {
    for (initial, release_time, reason) in [
        (1, 11, StopReason::IdleExpired),
        (1, 100, StopReason::HardExpired),
        (2, 1, StopReason::ClockRegressed),
    ] {
        let mut authority = session(5);
        admit(&mut authority, initial, 1, typed(1)).unwrap();
        let gate_called = Cell::new(false);
        let result = authority.release_checked(
            || seconds(release_time),
            id(1),
            |_, _, _| true,
            |_| {
                gate_called.set(true);
                Ok::<_, ()>(())
            },
        );
        assert_eq!(
            result,
            Err(ReleaseError::Authority(AuthorityError::Lease(
                SessionError::NotActive
            )))
        );
        assert!(!gate_called.get());
        assert!(
            matches!(authority.status().state, LeaseState::Stopping { reason: actual, .. } if actual == reason)
        );
    }
}

#[test]
fn time_and_native_identity_are_rechecked_after_admission_before_gate() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    authority.caller().handle().live.set(false);
    assert_eq!(
        authority.release_checked(
            || seconds(2),
            id(1),
            |caller, _, _| caller.handle().live.get(),
            |_| panic!("stale identity must not release gate")
        ),
        Err::<(), _>(ReleaseError::<()>::Authority(
            AuthorityError::ValidationRejected
        ))
    );
    authority.caller().handle().live.set(true);
    let mut times = [seconds(10), seconds(11)].into_iter();
    assert_eq!(
        authority.release_checked(
            || times.next().unwrap(),
            id(1),
            |_, _, _| true,
            |_| panic!("expired validation must not release gate")
        ),
        Err::<(), _>(ReleaseError::<()>::Authority(AuthorityError::Lease(
            SessionError::NotActive
        )))
    );
}

#[test]
fn gate_receives_the_original_immutable_narrowed_request_only_once() {
    let mut authority = session(5);
    let original = OperationRequest::new(
        id(1),
        binding(),
        OperationBinding::new(typed(1), HelperIdentity::from_bytes([7; 32]), scope(&[2])),
        OperationPayload::Typed(PayloadDigest::from_bytes([33; 32])),
    );
    authority
        .admit_checked(|| seconds(1), original.clone(), |_, _, _| true)
        .unwrap();
    authority
        .release_checked(
            || seconds(2),
            id(1),
            |_, grant, req| {
                assert_eq!(grant.binding(), &operation(typed(1)));
                assert_eq!(req, &original);
                true
            },
            |req| {
                assert_eq!(req, &original);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
    assert_eq!(
        release(&mut authority, 3, 1),
        Err(ReleaseError::Authority(AuthorityError::AlreadyReleased))
    );
}

#[test]
fn wrong_request_id_cannot_release_complete_or_refresh_an_operation() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    let before = authority.status();
    assert_eq!(
        release(&mut authority, 2, 2),
        Err(ReleaseError::Authority(AuthorityError::NoSuchOperation))
    );
    assert_eq!(
        authority.complete_operation(seconds(2), id(2)),
        Err(AuthorityError::NoSuchOperation)
    );
    assert_eq!(
        authority.record_progress(seconds(2), id(2)),
        Err(AuthorityError::NoSuchOperation)
    );
    assert_eq!(authority.status(), before);
    assert_eq!(
        authority.record_progress(seconds(2), id(1)),
        Err(AuthorityError::ProgressNotRunning)
    );
}

#[test]
fn useful_released_progress_and_completion_reset_idle_but_status_never_does() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    release(&mut authority, 2, 1).unwrap();
    for time in [9, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99] {
        authority.record_progress(seconds(time), id(1)).unwrap();
        let snapshot = authority.status();
        assert_eq!(snapshot, authority.status());
        assert_eq!(snapshot.next_deadline, Some(seconds((time + 10).min(100))));
    }
    assert_eq!(
        authority.record_progress(seconds(100), id(1)),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    assert!(matches!(
        authority.status().state,
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            ..
        }
    ));
}

#[test]
fn completion_at_expiry_cannot_resurrect_the_lease() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    release(&mut authority, 2, 1).unwrap();
    assert_eq!(
        authority.complete_operation(seconds(11), id(1)),
        Ok(LeaseState::Stopping {
            reason: StopReason::IdleExpired,
            cleanup_failed: false
        })
    );
    assert_eq!(authority.status().in_flight, None);
    assert_eq!(
        admit(&mut authority, 12, 2, typed(2)),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
}

#[test]
fn revoke_between_admit_and_release_denies_the_gate_and_preserves_budget() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    authority.stop(StopReason::Revoked);
    assert_eq!(
        authority.release_checked(
            || seconds(2),
            id(1),
            |_, _, _| panic!("no validation after stop"),
            |_| panic!("no gate after stop")
        ),
        Err::<(), _>(ReleaseError::<()>::Authority(AuthorityError::Lease(
            SessionError::NotActive
        )))
    );
    assert_eq!(authority.status().remaining_uses, 4);
    assert_eq!(
        authority.status().in_flight,
        Some((id(1), OperationPhase::Admitted))
    );
}

#[test]
fn stop_after_release_closes_all_later_work_until_positive_whole_session_cleanup() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    release(&mut authority, 2, 1).unwrap();
    authority.stop(StopReason::AuthorityChanged);
    assert!(!authority.status().state.is_terminal());
    assert_eq!(
        authority.record_progress(seconds(3), id(1)),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    assert_eq!(
        admit(&mut authority, 3, 2, typed(2)),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    authority.report_cleanup(Cleanup::Complete).unwrap();
    assert!(authority.status().state.is_terminal());
    assert_eq!(authority.status().in_flight, None);
    assert!(!authority.status().state.is_clean_shutdown());
}

#[test]
fn normal_shutdown_requires_positive_cleanup_and_cannot_mask_earlier_expiry() {
    let mut authority = session(5);
    authority.shutdown(seconds(1));
    assert!(!authority.status().state.is_clean_shutdown());
    authority.report_cleanup(Cleanup::Complete).unwrap();
    assert!(authority.status().state.is_clean_shutdown());
    assert_eq!(
        admit(&mut authority, 2, 1, typed(1)),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    let mut expired = session(5);
    expired.shutdown(seconds(10));
    expired.report_cleanup(Cleanup::Complete).unwrap();
    assert!(!expired.status().state.is_clean_shutdown());
    assert!(matches!(
        expired.status().state,
        LeaseState::Terminated {
            reason: StopReason::IdleExpired,
            ..
        }
    ));
}

#[test]
fn cleanup_failure_is_sticky_and_retains_the_in_flight_state_until_proven_cleanup() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    release(&mut authority, 2, 1).unwrap();
    authority.shutdown(seconds(3));
    authority.report_cleanup(Cleanup::Failed).unwrap();
    assert_eq!(
        authority.status().in_flight,
        Some((id(1), OperationPhase::Released))
    );
    assert!(!authority.status().state.is_terminal());
    authority.stop(StopReason::Revoked);
    authority.shutdown(seconds(4));
    authority.report_cleanup(Cleanup::Complete).unwrap();
    assert_eq!(
        authority.status().state,
        LeaseState::Terminated {
            reason: StopReason::NormalShutdown,
            cleanup_failed: true
        }
    );
    assert!(!authority.status().state.is_clean_shutdown());
    assert_eq!(authority.status().in_flight, None);
    assert_eq!(
        authority.report_cleanup(Cleanup::Complete),
        Err(AuthorityError::Lease(SessionError::InvalidTransition))
    );
}

#[test]
fn cleanup_cannot_be_reported_before_admission_is_closed() {
    let mut authority = session(5);
    assert_eq!(
        authority.report_cleanup(Cleanup::Complete),
        Err(AuthorityError::Lease(SessionError::InvalidTransition))
    );
    assert_eq!(authority.status().state, LeaseState::Active);
}

#[test]
fn dropping_live_authority_retains_the_handle_until_drop_but_claims_no_cleanup() {
    struct Handle(Arc<Mutex<bool>>);
    impl Drop for Handle {
        fn drop(&mut self) {
            *self.0.lock().unwrap() = true;
        }
    }
    let dropped = Arc::new(Mutex::new(false));
    let authority = SessionAuthority::new(
        binding(),
        RetainedCaller::new(Handle(dropped.clone())),
        LeaseLimits::standard(),
        Duration::ZERO,
        uses(1),
        vec![OperationGrant::new(operation(typed(1)), uses(1))],
    )
    .unwrap();
    assert!(!*dropped.lock().unwrap());
    assert!(!authority.status().state.is_terminal());
    drop(authority);
    assert!(*dropped.lock().unwrap());
}

#[test]
fn fresh_session_identity_rejects_requests_from_a_previous_coordinator() {
    let fresh = AuthorityBinding::new(
        SessionId::from_bytes([88; 32]),
        binding().audience(),
        binding().policy(),
        binding().installation(),
    );
    let mut authority = SessionAuthority::new(
        fresh,
        RetainedCaller::new(()),
        LeaseLimits::standard(),
        Duration::ZERO,
        uses(1),
        vec![OperationGrant::new(operation(typed(1)), uses(1))],
    )
    .unwrap();
    assert_eq!(
        authority.admit_checked(|| seconds(1), request(1, typed(1)), |_, _, _| true),
        Err(AuthorityError::BindingMismatch)
    );
    assert_eq!(authority.status().remaining_uses, 1);
}

#[test]
fn duplicate_selectors_empty_grants_and_duplicate_resources_are_invalid() {
    let create = |operations| {
        SessionAuthority::new(
            binding(),
            RetainedCaller::new(()),
            LeaseLimits::standard(),
            Duration::ZERO,
            uses(1),
            operations,
        )
    };
    assert!(matches!(create(vec![]), Err(AuthorityError::InvalidGrant)));
    for second in [
        typed(1),
        OperationTarget::Typed {
            operation: OperationId::from_bytes([1; 32]),
            definition: DefinitionDigest::from_bytes([99; 32]),
        },
    ] {
        assert!(matches!(
            create(vec![
                OperationGrant::new(operation(typed(1)), uses(1)),
                OperationGrant::new(operation(second), uses(2))
            ]),
            Err(AuthorityError::InvalidGrant)
        ));
    }
    assert_eq!(
        ResourceScope::new([ResourceId::from_bytes([1; 32]); 2]),
        Err(AuthorityError::InvalidGrant)
    );
}

#[test]
fn maximum_budgets_do_not_overflow_or_require_preallocation() {
    let mut authority = SessionAuthority::new(
        binding(),
        RetainedCaller::new(()),
        LeaseLimits::standard(),
        Duration::ZERO,
        uses(u64::MAX),
        vec![
            OperationGrant::new(operation(typed(1)), uses(u64::MAX)),
            OperationGrant::new(operation(typed(2)), uses(u64::MAX)),
        ],
    )
    .unwrap();
    authority
        .admit_checked(|| seconds(1), request(1, typed(1)), |_, _, _| true)
        .unwrap();
    assert_eq!(authority.status().remaining_uses, u64::MAX - 1);
    assert_eq!(
        authority.remaining_operation_uses(typed(1)),
        Some(u64::MAX - 1)
    );
    assert_eq!(authority.remaining_operation_uses(typed(2)), Some(u64::MAX));
}

#[test]
fn eight_hour_limit_and_unrepresentable_deadlines_remain_unchanged() {
    assert_eq!(MAX_HARD_TIMEOUT, seconds(8 * 60 * 60));
    assert!(LeaseLimits::from_administrator_policy(seconds(1), MAX_HARD_TIMEOUT).is_ok());
    assert_eq!(
        LeaseLimits::from_administrator_policy(
            seconds(1),
            MAX_HARD_TIMEOUT + Duration::from_nanos(1)
        ),
        Err(SessionError::InvalidLimits)
    );
    let invalid = SessionAuthority::new(
        binding(),
        RetainedCaller::new(()),
        LeaseLimits::standard(),
        Duration::MAX,
        uses(1),
        vec![OperationGrant::new(operation(typed(1)), uses(1))],
    );
    assert!(matches!(
        invalid,
        Err(AuthorityError::Lease(SessionError::InvalidClock))
    ));
}

#[test]
fn competing_callers_share_one_exclusive_admission_and_budget() {
    let authority = Arc::new(Mutex::new(session(5)));
    let barrier = Arc::new(Barrier::new(3));
    let threads: Vec<_> = (1..=2)
        .map(|number| {
            let authority = authority.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                admit(&mut authority.lock().unwrap(), 1, number, typed(number))
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(AuthorityError::Busy))
            .count(),
        1
    );
    assert_eq!(authority.lock().unwrap().status().remaining_uses, 4);
}

#[test]
fn reducing_authority_is_serialized_before_a_competing_release() {
    let mut initial = session(5);
    admit(&mut initial, 1, 1, typed(1)).unwrap();
    let authority = Arc::new(Mutex::new(initial));
    let (stopped, ready) = std::sync::mpsc::channel();
    let owner = authority.clone();
    let stopper = std::thread::spawn(move || {
        owner.lock().unwrap().stop(StopReason::Revoked);
        stopped.send(()).unwrap();
    });
    ready.recv().unwrap();
    assert_eq!(
        release(&mut authority.lock().unwrap(), 2, 1),
        Err(ReleaseError::Authority(AuthorityError::Lease(
            SessionError::NotActive
        )))
    );
    stopper.join().unwrap();
}

#[test]
fn errors_and_debug_handles_do_not_embed_payloads_or_native_error_text() {
    let error = ReleaseError::Gate("private helper output");
    assert_eq!(error.to_string(), "session native gate release failed");
    assert_eq!(format!("{error:?}"), "Gate(..)");
    assert_eq!(
        format!("{:?}", RetainedCaller::new("private caller detail")),
        "RetainedCaller(..)"
    );
    assert_eq!(
        format!("{:?}", PayloadDigest::from_bytes([255; 32])),
        "PayloadDigest(..)"
    );
}

#[test]
fn admitted_but_never_released_completion_spends_use_without_activity_refresh() {
    let mut authority = session(5);
    admit(&mut authority, 1, 1, typed(1)).unwrap();
    authority.complete_operation(seconds(9), id(1)).unwrap();
    assert_eq!(authority.status().next_deadline, Some(seconds(11)));
    assert_eq!(authority.status().remaining_uses, 4);
    assert_eq!(
        admit(&mut authority, 10, 1, typed(1)),
        Err(AuthorityError::Replay)
    );
}

#[test]
fn validation_clock_regression_rejects_without_spending_a_use() {
    let mut authority = session(5);
    let mut times = [seconds(2), seconds(1)].into_iter();
    assert_eq!(
        authority.admit_checked(
            || times.next().unwrap(),
            request(1, typed(1)),
            |_, _, _| true
        ),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    assert_eq!(authority.status().remaining_uses, 5);
    assert!(matches!(
        authority.status().state,
        LeaseState::Stopping {
            reason: StopReason::ClockRegressed,
            ..
        }
    ));
}

#[test]
fn near_duration_max_activity_clamps_to_hard_deadline_without_wrapping() {
    let start = Duration::MAX - seconds(100);
    let limits = LeaseLimits::from_administrator_policy(seconds(60), seconds(100)).unwrap();
    let mut authority = SessionAuthority::new(
        binding(),
        RetainedCaller::new(()),
        limits,
        start,
        uses(1),
        vec![OperationGrant::new(operation(typed(1)), uses(1))],
    )
    .unwrap();
    authority
        .admit_checked(|| start + seconds(1), request(1, typed(1)), |_, _, _| true)
        .unwrap();
    authority
        .release_checked(
            || start + seconds(2),
            id(1),
            |_, _, _| true,
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
    authority
        .record_progress(start + seconds(59), id(1))
        .unwrap();
    assert_eq!(authority.status().next_deadline, Some(Duration::MAX));
    assert_eq!(
        authority.record_progress(Duration::MAX, id(1)),
        Err(AuthorityError::Lease(SessionError::NotActive))
    );
    assert!(matches!(
        authority.status().state,
        LeaseState::Stopping {
            reason: StopReason::HardExpired,
            ..
        }
    ));
}
