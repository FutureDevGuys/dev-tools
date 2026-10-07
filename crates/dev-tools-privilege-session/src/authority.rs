//! Reusable local admission accounting for a single trusted coordinator.
//!
//! These types do not authenticate peers, hash documents, generate random IDs,
//! install timers, release native gates, or prove process cleanup. Product/native
//! adapters supply those observations. In particular, byte identity equality is
//! not native custody, and possession of a session or request ID is not authority.

use crate::{Cleanup, LeaseLifecycle, LeaseLimits, LeaseState, SessionError, StopReason};
use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

macro_rules! opaque_identity {
    ($($name:ident),+ $(,)?) => {$(
        /// An opaque product-supplied identity, not native authentication proof.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
            pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    )+};
}

opaque_identity!(
    SessionId,
    RequestId,
    AudienceId,
    PolicyIdentity,
    InstallationIdentity,
    OperationId,
    DefinitionDigest,
    PlanId,
    PlanDigest,
    HelperIdentity,
    ResourceId,
    PayloadDigest,
);

/// The adapter retains its actual native caller/workload handles here. Wrapping
/// an arbitrary value does not verify its provenance, liveness, or ownership.
/// No mutable or consuming handle accessor is provided while the grant lives.
pub struct RetainedCaller<C> {
    handle: C,
}

impl<C> RetainedCaller<C> {
    pub const fn new(handle: C) -> Self {
        Self { handle }
    }

    pub const fn handle(&self) -> &C {
        &self.handle
    }
}

impl<C> fmt::Debug for RetainedCaller<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedCaller(..)")
    }
}

/// Immutable approval identity. A new grant or coordinator restart must use a
/// fresh, nonreused session identity from the trusted adapter. No serialized
/// identity can recreate this crate's live budgets or replay history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityBinding {
    session: SessionId,
    audience: AudienceId,
    policy: PolicyIdentity,
    installation: InstallationIdentity,
}

impl AuthorityBinding {
    pub const fn new(
        session: SessionId,
        audience: AudienceId,
        policy: PolicyIdentity,
        installation: InstallationIdentity,
    ) -> Self {
        Self {
            session,
            audience,
            policy,
            installation,
        }
    }

    pub const fn session(&self) -> SessionId {
        self.session
    }
    pub const fn audience(&self) -> AudienceId {
        self.audience
    }
    pub const fn policy(&self) -> PolicyIdentity {
        self.policy
    }
    pub const fn installation(&self) -> InstallationIdentity {
        self.installation
    }
}

/// Closed typed/exact-plan alternatives. The product owns the operation schema,
/// helper protocol, and digest canonicalization. A plan digest must bind its
/// complete executable, argv, environment, streams, and declared resource effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationTarget {
    Typed {
        operation: OperationId,
        definition: DefinitionDigest,
    },
    ExactPlan {
        plan: PlanId,
        digest: PlanDigest,
    },
}

impl OperationTarget {
    fn same_selector(self, other: Self) -> bool {
        match (self, other) {
            (Self::Typed { operation: a, .. }, Self::Typed { operation: b, .. }) => a == b,
            (Self::ExactPlan { plan: a, .. }, Self::ExactPlan { plan: b, .. }) => a == b,
            _ => false,
        }
    }
}

/// A set of identities resolved by the native adapter, never raw path authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceScope(BTreeSet<ResourceId>);

impl ResourceScope {
    pub fn new(resources: impl IntoIterator<Item = ResourceId>) -> Result<Self, AuthorityError> {
        let mut set = BTreeSet::new();
        for resource in resources {
            if !set.insert(resource) {
                return Err(AuthorityError::InvalidGrant);
            }
        }
        Ok(Self(set))
    }

    pub fn iter(&self) -> impl Iterator<Item = &ResourceId> {
        self.0.iter()
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationBinding {
    target: OperationTarget,
    helper: HelperIdentity,
    resources: ResourceScope,
}

impl OperationBinding {
    pub const fn new(
        target: OperationTarget,
        helper: HelperIdentity,
        resources: ResourceScope,
    ) -> Self {
        Self {
            target,
            helper,
            resources,
        }
    }

    pub const fn target(&self) -> OperationTarget {
        self.target
    }
    pub const fn helper(&self) -> HelperIdentity {
        self.helper
    }
    pub const fn resources(&self) -> &ResourceScope {
        &self.resources
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationGrant {
    binding: OperationBinding,
    uses: NonZeroU64,
}

impl OperationGrant {
    pub const fn new(binding: OperationBinding, uses: NonZeroU64) -> Self {
        Self { binding, uses }
    }

    pub const fn binding(&self) -> &OperationBinding {
        &self.binding
    }
    pub const fn maximum_uses(&self) -> NonZeroU64 {
        self.uses
    }
}

/// Typed requests bind the validated input bytes; exact-plan requests carry no
/// replacement input. The adapter must verify the payload digest and interpret
/// the input against the approved closed schema before admission and gate release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPayload {
    Typed(PayloadDigest),
    ExactPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRequest {
    id: RequestId,
    authority: AuthorityBinding,
    operation: OperationBinding,
    payload: OperationPayload,
}

impl OperationRequest {
    pub const fn new(
        id: RequestId,
        authority: AuthorityBinding,
        operation: OperationBinding,
        payload: OperationPayload,
    ) -> Self {
        Self {
            id,
            authority,
            operation,
            payload,
        }
    }

    pub const fn id(&self) -> RequestId {
        self.id
    }
    pub const fn authority(&self) -> AuthorityBinding {
        self.authority
    }
    pub const fn operation(&self) -> &OperationBinding {
        &self.operation
    }
    pub const fn payload(&self) -> OperationPayload {
        self.payload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPhase {
    Admitted,
    Released,
    /// A gate call failed, so whether work started must be positively resolved.
    ReleaseFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub state: LeaseState,
    pub remaining_uses: u64,
    pub next_deadline: Option<Duration>,
    pub in_flight: Option<(RequestId, OperationPhase)>,
}

struct OperationBudget {
    grant: OperationGrant,
    remaining: u64,
}

struct InFlight {
    request: OperationRequest,
    operation_index: usize,
    phase: OperationPhase,
}

/// One exclusive coordinator owns admission, gate release, stop, and cleanup.
/// There is no clone, serialization, mutable binding access, detached execution
/// permit, delegation, queue, or automatic retry. Callbacks must be bounded and
/// must not reenter the coordinator. Native expiry/owner-death enforcement must
/// remain independent of these synchronous calls and blocked command I/O.
///
/// Accepted request IDs, including failed launches, remain remembered until the
/// authority is dropped. Replay storage grows only on consumed admissions and
/// is bounded by the approved total use budget, which product policy must cap.
///
/// ```compile_fail
/// use dev_tools_privilege_session::SessionAuthority;
/// fn duplicate<C>(authority: SessionAuthority<C>) {
///     let second_owner = authority.clone();
/// }
/// ```
pub struct SessionAuthority<C> {
    binding: AuthorityBinding,
    caller: RetainedCaller<C>,
    lifecycle: LeaseLifecycle,
    operations: Vec<OperationBudget>,
    accepted: BTreeSet<RequestId>,
    in_flight: Option<InFlight>,
}

impl<C> SessionAuthority<C> {
    pub fn new(
        binding: AuthorityBinding,
        caller: RetainedCaller<C>,
        limits: LeaseLimits,
        approved_at: Duration,
        total_uses: NonZeroU64,
        operations: Vec<OperationGrant>,
    ) -> Result<Self, AuthorityError> {
        if operations.is_empty() {
            return Err(AuthorityError::InvalidGrant);
        }
        for (index, operation) in operations.iter().enumerate() {
            if operations[..index]
                .iter()
                .any(|prior| prior.binding.target.same_selector(operation.binding.target))
            {
                return Err(AuthorityError::InvalidGrant);
            }
        }
        let lifecycle = LeaseLifecycle::new(limits, approved_at, total_uses)?;
        Ok(Self {
            binding,
            caller,
            lifecycle,
            operations: operations
                .into_iter()
                .map(|grant| OperationBudget {
                    remaining: grant.uses.get(),
                    grant,
                })
                .collect(),
            accepted: BTreeSet::new(),
            in_flight: None,
        })
    }

    pub const fn binding(&self) -> AuthorityBinding {
        self.binding
    }
    pub const fn caller(&self) -> &RetainedCaller<C> {
        &self.caller
    }

    pub fn grants(&self) -> impl Iterator<Item = &OperationGrant> {
        self.operations.iter().map(|operation| &operation.grant)
    }

    pub fn remaining_operation_uses(&self, target: OperationTarget) -> Option<u64> {
        self.operations
            .iter()
            .find(|operation| operation.grant.binding.target == target)
            .map(|operation| operation.remaining)
    }

    /// Snapshot only; neither reads a clock nor refreshes idle activity.
    pub fn status(&self) -> AuthorityStatus {
        AuthorityStatus {
            state: self.lifecycle.state(),
            remaining_uses: self.lifecycle.remaining_uses(),
            next_deadline: self.lifecycle.next_deadline(),
            in_flight: self
                .in_flight
                .as_ref()
                .map(|flight| (flight.request.id, flight.phase)),
        }
    }

    pub fn poll(&mut self, now: Duration) -> LeaseState {
        self.lifecycle.poll(now)
    }

    /// Validate without effects, then consume both budgets exactly once. Native
    /// validation must check current peer/owner/workload identity, generation,
    /// held helper/resource custody, and typed input/effect narrowing. The clock
    /// is sampled again after validation so validation cannot age an admission
    /// past its deadline. Rejected/busy/replayed requests consume nothing and
    /// cannot refresh idle time. Admission alone does not release a child gate.
    pub fn admit_checked<N, V>(
        &mut self,
        mut now: N,
        request: OperationRequest,
        validate: V,
    ) -> Result<RequestId, AuthorityError>
    where
        N: FnMut() -> Duration,
        V: FnOnce(&RetainedCaller<C>, &OperationGrant, &OperationRequest) -> bool,
    {
        self.require_active(now())?;
        if request.authority != self.binding {
            return Err(AuthorityError::BindingMismatch);
        }
        if self.accepted.contains(&request.id) {
            return Err(AuthorityError::Replay);
        }
        if self.in_flight.is_some() {
            return Err(AuthorityError::Busy);
        }
        let index = self
            .operations
            .iter()
            .position(|operation| {
                operation
                    .grant
                    .binding
                    .target
                    .same_selector(request.operation.target)
            })
            .ok_or(AuthorityError::OperationNotGranted)?;
        let operation = &self.operations[index];
        let approved = &operation.grant.binding;
        if approved.target != request.operation.target
            || approved.helper != request.operation.helper
        {
            return Err(AuthorityError::OperationMismatch);
        }
        let resources_valid = match approved.target {
            OperationTarget::Typed { .. } => request
                .operation
                .resources
                .is_subset_of(&approved.resources),
            OperationTarget::ExactPlan { .. } => request.operation.resources == approved.resources,
        };
        if !resources_valid {
            return Err(AuthorityError::ResourcesOutsideGrant);
        }
        if !matches!(
            (approved.target, request.payload),
            (OperationTarget::Typed { .. }, OperationPayload::Typed(_))
                | (
                    OperationTarget::ExactPlan { .. },
                    OperationPayload::ExactPlan
                )
        ) {
            return Err(AuthorityError::InvalidPayload);
        }
        if operation.remaining == 0 {
            return Err(AuthorityError::OperationUsesExhausted);
        }
        if self.lifecycle.remaining_uses() == 0 {
            return Err(AuthorityError::Lease(SessionError::UsesExhausted));
        }
        if !validate(&self.caller, &operation.grant, &request) {
            return Err(AuthorityError::ValidationRejected);
        }
        self.lifecycle.admit(now())?;
        self.operations[index].remaining -= 1;
        let id = request.id;
        self.accepted.insert(id);
        self.in_flight = Some(InFlight {
            request,
            operation_index: index,
            phase: OperationPhase::Admitted,
        });
        Ok(id)
    }

    /// Recheck native authority and time, then synchronously attempt one gate
    /// release while holding the same exclusive owner used by stop/revoke. The
    /// gate receives the retained immutable request, never replacement fields.
    /// A failed release may have started work: no refund or implicit retry occurs.
    /// It remains in flight until positive completion or whole-session cleanup.
    /// The gate adapter must enforce the independent native deadline and must not
    /// block on workload execution or its streams.
    pub fn release_checked<N, V, F, T, E>(
        &mut self,
        mut now: N,
        id: RequestId,
        validate: V,
        release_gate: F,
    ) -> Result<T, ReleaseError<E>>
    where
        N: FnMut() -> Duration,
        V: FnOnce(&RetainedCaller<C>, &OperationGrant, &OperationRequest) -> bool,
        F: FnOnce(&OperationRequest) -> Result<T, E>,
    {
        self.require_active(now())
            .map_err(ReleaseError::Authority)?;
        let flight = self.matching_flight(id).map_err(ReleaseError::Authority)?;
        if flight.phase != OperationPhase::Admitted {
            return Err(ReleaseError::Authority(AuthorityError::AlreadyReleased));
        }
        if !validate(
            &self.caller,
            &self.operations[flight.operation_index].grant,
            &flight.request,
        ) {
            return Err(ReleaseError::Authority(AuthorityError::ValidationRejected));
        }
        self.require_active(now())
            .map_err(ReleaseError::Authority)?;
        let flight = self
            .in_flight
            .as_mut()
            .expect("matched in-flight operation is retained");
        // Mark before calling external code; unwinding cannot restore a reusable
        // gate or refund a use. Native coordinator-death cleanup remains required.
        flight.phase = OperationPhase::ReleaseFailed;
        match release_gate(&flight.request) {
            Ok(value) => {
                flight.phase = OperationPhase::Released;
                Ok(value)
            }
            Err(error) => Err(ReleaseError::Gate(error)),
        }
    }

    /// A trusted useful-progress observation from this released operation only.
    /// Output bytes, status reads, client heartbeats, and request traffic are not
    /// such evidence. Product policy decides which native observations qualify.
    pub fn record_progress(&mut self, now: Duration, id: RequestId) -> Result<(), AuthorityError> {
        if self.matching_flight(id)?.phase != OperationPhase::Released {
            return Err(AuthorityError::ProgressNotRunning);
        }
        self.lifecycle.record_activity(now)?;
        Ok(())
    }

    /// The adapter positively observed this operation's entire native boundary
    /// cleaned up (or proved the gate never released). A released operation's
    /// trusted completion refreshes idle only while the lease is still active.
    /// Completion at/after expiry returns the stopping state and never revives
    /// authority. Completing one operation never terminates a reusable session.
    pub fn complete_operation(
        &mut self,
        now: Duration,
        id: RequestId,
    ) -> Result<LeaseState, AuthorityError> {
        let released = self.matching_flight(id)?.phase == OperationPhase::Released;
        let state = self.lifecycle.poll(now);
        if state == LeaseState::Active && released {
            self.lifecycle.record_activity(now)?;
        }
        self.in_flight = None;
        Ok(self.lifecycle.state())
    }

    pub fn stop(&mut self, reason: StopReason) {
        self.lifecycle.stop(reason);
    }

    /// Normal controller completion closes admission but still requires positive
    /// cleanup of all retained domains. It cannot overwrite an earlier failure.
    pub fn shutdown(&mut self, now: Duration) {
        self.lifecycle.shutdown(now);
    }

    /// Whole-session cleanup includes the controller and all operation domains.
    /// A failed observation retains both the caller handle and in-flight record.
    pub fn report_cleanup(&mut self, cleanup: Cleanup) -> Result<(), AuthorityError> {
        self.lifecycle.report_cleanup(cleanup)?;
        if cleanup == Cleanup::Complete {
            self.in_flight = None;
        }
        Ok(())
    }

    fn require_active(&mut self, now: Duration) -> Result<(), AuthorityError> {
        if self.lifecycle.poll(now) == LeaseState::Active {
            Ok(())
        } else {
            Err(AuthorityError::Lease(SessionError::NotActive))
        }
    }

    fn matching_flight(&self, id: RequestId) -> Result<&InFlight, AuthorityError> {
        self.in_flight
            .as_ref()
            .filter(|flight| flight.request.id == id)
            .ok_or(AuthorityError::NoSuchOperation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityError {
    Lease(SessionError),
    InvalidGrant,
    BindingMismatch,
    OperationNotGranted,
    OperationMismatch,
    ResourcesOutsideGrant,
    InvalidPayload,
    Replay,
    Busy,
    OperationUsesExhausted,
    ValidationRejected,
    NoSuchOperation,
    AlreadyReleased,
    ProgressNotRunning,
}

impl From<SessionError> for AuthorityError {
    fn from(error: SessionError) -> Self {
        Self::Lease(error)
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease(error) => error.fmt(formatter),
            Self::InvalidGrant => formatter.write_str("session grant is invalid"),
            Self::BindingMismatch => formatter.write_str("session authority binding differs"),
            Self::OperationNotGranted => formatter.write_str("session operation is not granted"),
            Self::OperationMismatch => formatter.write_str("session operation identity differs"),
            Self::ResourcesOutsideGrant => formatter.write_str("session resource scope differs"),
            Self::InvalidPayload => formatter.write_str("session operation payload kind differs"),
            Self::Replay => formatter.write_str("session request was already admitted"),
            Self::Busy => formatter.write_str("session operation is already in flight"),
            Self::OperationUsesExhausted => {
                formatter.write_str("session operation use budget is exhausted")
            }
            Self::ValidationRejected => formatter.write_str("session native validation rejected"),
            Self::NoSuchOperation => {
                formatter.write_str("session in-flight operation does not match")
            }
            Self::AlreadyReleased => {
                formatter.write_str("session gate release was already attempted")
            }
            Self::ProgressNotRunning => {
                formatter.write_str("session operation has not been released")
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReleaseError<E> {
    Authority(AuthorityError),
    Gate(E),
}

impl<E> fmt::Debug for ReleaseError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => formatter.debug_tuple("Authority").field(error).finish(),
            Self::Gate(_) => formatter.write_str("Gate(..)"),
        }
    }
}

impl<E> fmt::Display for ReleaseError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => error.fmt(formatter),
            // Native error/output values must not leak through control results.
            Self::Gate(_) => formatter.write_str("session native gate release failed"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ReleaseError<E> {}
