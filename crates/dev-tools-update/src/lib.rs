//! Product-neutral orchestration for the standalone update contract.
//!
//! The caller owns release authority, persistent layout, health checks, setup,
//! presentation, and privilege. This crate owns only operation ordering and the
//! invariant that local operations cannot accidentally cross the network seam.

use dev_tools_product::{
    CacheFreshness, CommonOperation, ErrorKind, ExitCategory, InstallationState, OperationOutcome,
    OperationResult, ProductId, OPERATION_RESULT_SCHEMA,
};
use dev_tools_release::VerifiedRelease;
use semver::Version;
use std::error::Error;
use std::fmt;

pub const MAX_CACHE_AGE_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdatePolicy {
    product: ProductId,
    max_cache_age_seconds: u64,
}

impl UpdatePolicy {
    pub fn new(product: ProductId, max_cache_age_seconds: u64) -> Result<Self, UpdateError> {
        if max_cache_age_seconds == 0 || max_cache_age_seconds > MAX_CACHE_AGE_SECONDS {
            return Err(UpdateError::new(UpdateErrorKind::InvalidConfiguration));
        }
        Ok(Self {
            product,
            max_cache_age_seconds,
        })
    }

    pub fn standard(product: ProductId) -> Self {
        Self {
            product,
            max_cache_age_seconds: MAX_CACHE_AGE_SECONDS,
        }
    }

    pub fn product(&self) -> &ProductId {
        &self.product
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRequest {
    operation: CommonOperation,
    offline: bool,
}

impl OperationRequest {
    pub const fn status() -> Self {
        Self {
            operation: CommonOperation::UpdateStatus,
            offline: true,
        }
    }

    pub const fn check() -> Self {
        Self {
            operation: CommonOperation::UpdateCheck,
            offline: false,
        }
    }

    pub const fn install(offline: bool) -> Self {
        Self {
            operation: CommonOperation::UpdateInstall,
            offline,
        }
    }

    pub const fn apply(offline: bool) -> Self {
        Self {
            operation: CommonOperation::UpdateApply,
            offline,
        }
    }

    pub const fn rollback() -> Self {
        Self {
            operation: CommonOperation::UpdateRollback,
            offline: true,
        }
    }

    pub const fn operation(self) -> CommonOperation {
        self.operation
    }

    pub const fn is_offline(self) -> bool {
        self.offline
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationSnapshot {
    state: InstallationState,
    version: Option<Version>,
    setup_required: bool,
}

impl InstallationSnapshot {
    pub fn absent() -> Self {
        Self {
            state: InstallationState::Absent,
            version: None,
            setup_required: false,
        }
    }

    pub fn managed(version: Option<Version>) -> Self {
        Self {
            state: InstallationState::Managed,
            version,
            setup_required: false,
        }
    }

    pub fn external(version: Option<Version>) -> Self {
        Self {
            state: InstallationState::External,
            version,
            setup_required: false,
        }
    }

    pub fn unknown(version: Option<Version>) -> Self {
        Self {
            state: InstallationState::Unknown,
            version,
            setup_required: false,
        }
    }

    pub fn requires_setup(version: Option<Version>) -> Self {
        Self {
            state: InstallationState::Unknown,
            version,
            setup_required: true,
        }
    }

    pub fn state(&self) -> InstallationState {
        self.state
    }

    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    fn setup_required(&self) -> bool {
        self.setup_required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCandidate {
    verified: VerifiedRelease,
    checked_at_unix: u64,
    artifact_available: bool,
}

impl AuthenticatedCandidate {
    pub fn new(
        verified: VerifiedRelease,
        checked_at_unix: u64,
        artifact_available: bool,
    ) -> Result<Self, UpdateError> {
        if verified.product.is_empty()
            || verified.target.is_empty()
            || verified.artifact_length == 0
            || !verified.version.pre.is_empty()
        {
            return Err(UpdateError::new(UpdateErrorKind::InvalidConfiguration));
        }
        Ok(Self {
            verified,
            checked_at_unix,
            artifact_available,
        })
    }

    pub fn verified(&self) -> &VerifiedRelease {
        &self.verified
    }

    pub fn checked_at_unix(&self) -> u64 {
        self.checked_at_unix
    }

    pub fn artifact_available(&self) -> bool {
        self.artifact_available
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateErrorKind {
    Operational,
    InvalidInvocation,
    InvalidConfiguration,
    Blocked,
    Unsupported,
    RequiresSetup,
    Network,
    Authenticity,
    Integrity,
    Authority,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateError {
    kind: UpdateErrorKind,
}

impl UpdateError {
    pub const fn new(kind: UpdateErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> UpdateErrorKind {
        self.kind
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            UpdateErrorKind::Operational => "update operation failed",
            UpdateErrorKind::InvalidInvocation => "update invocation is invalid",
            UpdateErrorKind::InvalidConfiguration => "update configuration is invalid",
            UpdateErrorKind::Blocked => "update operation is blocked",
            UpdateErrorKind::Unsupported => "update operation is unsupported",
            UpdateErrorKind::RequiresSetup => "product setup is required",
            UpdateErrorKind::Network => "update network operation failed",
            UpdateErrorKind::Authenticity => "update authenticity verification failed",
            UpdateErrorKind::Integrity => "update integrity verification failed",
            UpdateErrorKind::Authority => "update authority verification failed",
            UpdateErrorKind::Interrupted => "update operation was interrupted",
        })
    }
}

impl Error for UpdateError {}

pub trait UpdateAdapter {
    fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError>;

    /// Loads locally cached release evidence and never accesses the network.
    fn load_authenticated_candidate(
        &mut self,
    ) -> Result<Option<AuthenticatedCandidate>, UpdateError>;

    /// Performs the explicit product-owned network discovery and authentication step.
    fn refresh_authenticated_candidate(&mut self) -> Result<AuthenticatedCandidate, UpdateError>;

    fn install(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError>;
    fn apply(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError>;
    fn rollback(&mut self) -> Result<bool, UpdateError>;
}

pub fn execute<A: UpdateAdapter>(
    policy: &UpdatePolicy,
    request: OperationRequest,
    now_unix: u64,
    adapter: &mut A,
) -> OperationResult {
    let installation = match adapter.inspect() {
        Ok(installation) => installation,
        Err(error) => return error_result(policy, request.operation, None, error),
    };
    if installation.state == InstallationState::External {
        return operation_result(
            policy,
            request.operation,
            OperationOutcome::External,
            false,
            ExitCategory::Completed,
            None,
            &installation,
            None,
            Some(CacheFreshness::NotApplicable),
        );
    }
    if installation.setup_required() {
        return operation_result(
            policy,
            request.operation,
            OperationOutcome::RequiresSetup,
            false,
            ExitCategory::Blocked,
            Some(ErrorKind::RequiresSetup),
            &installation,
            None,
            Some(CacheFreshness::NotApplicable),
        );
    }

    match request.operation {
        CommonOperation::UpdateStatus => status(policy, request, now_unix, adapter, installation),
        CommonOperation::UpdateCheck => check(policy, request, now_unix, adapter, installation),
        CommonOperation::UpdateInstall => {
            if installation.state != InstallationState::Absent {
                return blocked_state(policy, request.operation, &installation);
            }
            mutate(policy, request, now_unix, adapter, installation, true)
        }
        CommonOperation::UpdateApply => {
            if installation.state != InstallationState::Managed {
                return blocked_state(policy, request.operation, &installation);
            }
            mutate(policy, request, now_unix, adapter, installation, false)
        }
        CommonOperation::UpdateRollback => {
            if installation.state != InstallationState::Managed {
                return blocked_state(policy, request.operation, &installation);
            }
            match adapter.rollback() {
                Ok(changed) => operation_result(
                    policy,
                    request.operation,
                    if changed {
                        OperationOutcome::RolledBack
                    } else {
                        OperationOutcome::NoOp
                    },
                    changed,
                    ExitCategory::Completed,
                    None,
                    &installation,
                    None,
                    Some(CacheFreshness::NotApplicable),
                ),
                Err(error) => error_result(policy, request.operation, Some(&installation), error),
            }
        }
        CommonOperation::Doctor => error_result(
            policy,
            request.operation,
            Some(&installation),
            UpdateError::new(UpdateErrorKind::InvalidInvocation),
        ),
    }
}

fn status<A: UpdateAdapter>(
    policy: &UpdatePolicy,
    request: OperationRequest,
    now_unix: u64,
    adapter: &mut A,
    installation: InstallationSnapshot,
) -> OperationResult {
    let candidate = match adapter.load_authenticated_candidate() {
        Ok(candidate) => candidate,
        Err(error) => return error_result(policy, request.operation, Some(&installation), error),
    };
    let Some(candidate) = candidate else {
        return operation_result(
            policy,
            request.operation,
            OperationOutcome::Unknown,
            false,
            ExitCategory::Completed,
            None,
            &installation,
            None,
            Some(CacheFreshness::Absent),
        );
    };
    if let Err(error) = validate_candidate(policy, &candidate) {
        return error_result(policy, request.operation, Some(&installation), error);
    }
    let freshness = cache_freshness(policy, &candidate, now_unix);
    let outcome = if freshness == CacheFreshness::Expired {
        OperationOutcome::Unknown
    } else {
        release_outcome(&installation, &candidate)
    };
    operation_result(
        policy,
        request.operation,
        outcome,
        false,
        ExitCategory::Completed,
        None,
        &installation,
        Some(&candidate),
        Some(freshness),
    )
}

fn check<A: UpdateAdapter>(
    policy: &UpdatePolicy,
    request: OperationRequest,
    now_unix: u64,
    adapter: &mut A,
    installation: InstallationSnapshot,
) -> OperationResult {
    let candidate = match adapter.refresh_authenticated_candidate() {
        Ok(candidate) => candidate,
        Err(error) => return error_result(policy, request.operation, Some(&installation), error),
    };
    if let Err(error) = validate_candidate(policy, &candidate) {
        return error_result(policy, request.operation, Some(&installation), error);
    }
    operation_result(
        policy,
        request.operation,
        release_outcome(&installation, &candidate),
        false,
        ExitCategory::Completed,
        None,
        &installation,
        Some(&candidate),
        Some(cache_freshness(policy, &candidate, now_unix)),
    )
}

fn mutate<A: UpdateAdapter>(
    policy: &UpdatePolicy,
    request: OperationRequest,
    now_unix: u64,
    adapter: &mut A,
    installation: InstallationSnapshot,
    install: bool,
) -> OperationResult {
    let candidate = if request.offline {
        match adapter.load_authenticated_candidate() {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return blocked_state(policy, request.operation, &installation),
            Err(error) => {
                return error_result(policy, request.operation, Some(&installation), error)
            }
        }
    } else {
        match adapter.refresh_authenticated_candidate() {
            Ok(candidate) => candidate,
            Err(error) => {
                return error_result(policy, request.operation, Some(&installation), error)
            }
        }
    };
    if let Err(error) = validate_candidate(policy, &candidate) {
        return error_result(policy, request.operation, Some(&installation), error);
    }
    if !candidate.artifact_available {
        return blocked_state(policy, request.operation, &installation);
    }
    if installation
        .version
        .as_ref()
        .is_some_and(|installed| installed >= &candidate.verified.version)
    {
        return operation_result(
            policy,
            request.operation,
            OperationOutcome::NoOp,
            false,
            ExitCategory::Completed,
            None,
            &installation,
            Some(&candidate),
            Some(cache_freshness(policy, &candidate, now_unix)),
        );
    }
    let changed = if install {
        adapter.install(&candidate)
    } else {
        adapter.apply(&candidate)
    };
    match changed {
        Ok(changed) => operation_result(
            policy,
            request.operation,
            if changed {
                if install {
                    OperationOutcome::Installed
                } else {
                    OperationOutcome::Updated
                }
            } else {
                OperationOutcome::NoOp
            },
            changed,
            ExitCategory::Completed,
            None,
            &installation,
            Some(&candidate),
            Some(cache_freshness(policy, &candidate, now_unix)),
        ),
        Err(error) => error_result(policy, request.operation, Some(&installation), error),
    }
}

fn validate_candidate(
    policy: &UpdatePolicy,
    candidate: &AuthenticatedCandidate,
) -> Result<(), UpdateError> {
    if candidate.verified.product != policy.product.as_str() {
        return Err(UpdateError::new(UpdateErrorKind::Authority));
    }
    Ok(())
}

fn cache_freshness(
    policy: &UpdatePolicy,
    candidate: &AuthenticatedCandidate,
    now_unix: u64,
) -> CacheFreshness {
    match now_unix.checked_sub(candidate.checked_at_unix) {
        Some(age) if age <= policy.max_cache_age_seconds => CacheFreshness::Fresh,
        _ => CacheFreshness::Expired,
    }
}

fn release_outcome(
    installation: &InstallationSnapshot,
    candidate: &AuthenticatedCandidate,
) -> OperationOutcome {
    if installation.state != InstallationState::Managed {
        return OperationOutcome::Unknown;
    }
    match installation.version.as_ref() {
        Some(installed) if installed >= &candidate.verified.version => OperationOutcome::Current,
        Some(_) => OperationOutcome::Stale,
        None => OperationOutcome::Unknown,
    }
}

fn blocked_state(
    policy: &UpdatePolicy,
    operation: CommonOperation,
    installation: &InstallationSnapshot,
) -> OperationResult {
    operation_result(
        policy,
        operation,
        OperationOutcome::Blocked,
        false,
        ExitCategory::Blocked,
        Some(ErrorKind::Blocked),
        installation,
        None,
        Some(CacheFreshness::NotApplicable),
    )
}

fn error_result(
    policy: &UpdatePolicy,
    operation: CommonOperation,
    installation: Option<&InstallationSnapshot>,
    error: UpdateError,
) -> OperationResult {
    let (outcome, category, error_kind) = match error.kind {
        UpdateErrorKind::Operational => (
            OperationOutcome::Failed,
            ExitCategory::OperationalFailure,
            ErrorKind::Operational,
        ),
        UpdateErrorKind::InvalidInvocation => (
            OperationOutcome::Failed,
            ExitCategory::InvalidInput,
            ErrorKind::InvalidInvocation,
        ),
        UpdateErrorKind::InvalidConfiguration => (
            OperationOutcome::Failed,
            ExitCategory::InvalidInput,
            ErrorKind::InvalidConfiguration,
        ),
        UpdateErrorKind::Blocked => (
            OperationOutcome::Blocked,
            ExitCategory::Blocked,
            ErrorKind::Blocked,
        ),
        UpdateErrorKind::Unsupported => (
            OperationOutcome::Unsupported,
            ExitCategory::Blocked,
            ErrorKind::Unsupported,
        ),
        UpdateErrorKind::RequiresSetup => (
            OperationOutcome::RequiresSetup,
            ExitCategory::Blocked,
            ErrorKind::RequiresSetup,
        ),
        UpdateErrorKind::Network => (
            OperationOutcome::Failed,
            ExitCategory::OperationalFailure,
            ErrorKind::Network,
        ),
        UpdateErrorKind::Authenticity => (
            OperationOutcome::AuthenticityViolation,
            ExitCategory::AuthorityViolation,
            ErrorKind::Authenticity,
        ),
        UpdateErrorKind::Integrity => (
            OperationOutcome::IntegrityViolation,
            ExitCategory::AuthorityViolation,
            ErrorKind::Integrity,
        ),
        UpdateErrorKind::Authority => (
            OperationOutcome::AuthorityViolation,
            ExitCategory::AuthorityViolation,
            ErrorKind::Authority,
        ),
        UpdateErrorKind::Interrupted => (
            OperationOutcome::Interrupted,
            ExitCategory::Interrupted,
            ErrorKind::Interrupted,
        ),
    };
    operation_result(
        policy,
        operation,
        outcome,
        false,
        category,
        Some(error_kind),
        installation.unwrap_or(&InstallationSnapshot::unknown(None)),
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn operation_result(
    policy: &UpdatePolicy,
    operation: CommonOperation,
    outcome: OperationOutcome,
    changed: bool,
    category: ExitCategory,
    error_kind: Option<ErrorKind>,
    installation: &InstallationSnapshot,
    candidate: Option<&AuthenticatedCandidate>,
    cache_freshness: Option<CacheFreshness>,
) -> OperationResult {
    OperationResult {
        schema: OPERATION_RESULT_SCHEMA,
        product: policy.product.clone(),
        operation,
        outcome,
        changed,
        installed_version: installation.version.as_ref().map(ToString::to_string),
        available_version: candidate.map(|candidate| candidate.verified.version.to_string()),
        cache_freshness,
        installation_state: Some(installation.state),
        exit_code: category.code(),
        error_kind,
    }
}
