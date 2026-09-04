use serde::Serialize;
use std::error::Error;
use std::fmt;

pub const OPERATION_RESULT_SCHEMA: &str = "dev-tools-operation-result-v1";
pub const BUILD_INFO_SCHEMA: &str = "dev-tools-build-info-v1";
pub const OPERATION_RESULT_JSON_SCHEMA: &str =
    include_str!("../schema/dev-tools-operation-result-v1.schema.json");
pub const BUILD_INFO_JSON_SCHEMA: &str =
    include_str!("../schema/dev-tools-build-info-v1.schema.json");

const MAX_PRODUCT_ID_LENGTH: usize = 64;
const MAX_IDENTITY_FIELD_LENGTH: usize = 128;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProductId(String);

impl ProductId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        let valid_start = value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        let valid = !value.is_empty() && value.len() <= MAX_PRODUCT_ID_LENGTH && valid_start;
        let valid = valid
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid {
            return Err(ContractError::invalid_product_id());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProductId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommonOperation {
    Doctor,
    UpdateStatus,
    UpdateCheck,
    UpdateInstall,
    UpdateApply,
    UpdateRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Completed,
    NoOp,
    Current,
    Stale,
    Unknown,
    External,
    Installed,
    Updated,
    RolledBack,
    Blocked,
    Deferred,
    Unsupported,
    RequiresSetup,
    Failed,
    AuthenticityViolation,
    IntegrityViolation,
    AuthorityViolation,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheFreshness {
    Fresh,
    Expired,
    Absent,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    Managed,
    External,
    Absent,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Operational,
    InvalidInvocation,
    InvalidConfiguration,
    Blocked,
    Deferred,
    Unsupported,
    RequiresSetup,
    Network,
    Authenticity,
    Integrity,
    Authority,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitCategory {
    Completed,
    OperationalFailure,
    InvalidInput,
    Blocked,
    AuthorityViolation,
    Interrupted,
}

impl ExitCategory {
    pub const fn code(self) -> i32 {
        match self {
            Self::Completed => 0,
            Self::OperationalFailure => 1,
            Self::InvalidInput => 2,
            Self::Blocked => 3,
            Self::AuthorityViolation => 4,
            Self::Interrupted => 130,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationResult {
    pub schema: &'static str,
    pub product: ProductId,
    pub operation: CommonOperation,
    pub outcome: OperationOutcome,
    pub changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_freshness: Option<CacheFreshness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_state: Option<InstallationState>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<ErrorKind>,
}

impl OperationResult {
    pub fn completed(
        product: ProductId,
        operation: CommonOperation,
        outcome: OperationOutcome,
        changed: bool,
    ) -> Result<Self, ContractError> {
        if !matches!(
            outcome,
            OperationOutcome::Completed
                | OperationOutcome::NoOp
                | OperationOutcome::Current
                | OperationOutcome::Stale
                | OperationOutcome::Unknown
                | OperationOutcome::External
                | OperationOutcome::Installed
                | OperationOutcome::Updated
                | OperationOutcome::RolledBack
        ) {
            return Err(ContractError::inconsistent_outcome());
        }
        Ok(Self::base(
            product,
            operation,
            outcome,
            changed,
            ExitCategory::Completed,
            None,
        ))
    }

    pub fn blocked(
        product: ProductId,
        operation: CommonOperation,
        outcome: OperationOutcome,
        error_kind: ErrorKind,
    ) -> Result<Self, ContractError> {
        let consistent = matches!(
            (outcome, error_kind),
            (OperationOutcome::Blocked, ErrorKind::Blocked)
                | (OperationOutcome::Deferred, ErrorKind::Deferred)
                | (OperationOutcome::Unsupported, ErrorKind::Unsupported)
                | (OperationOutcome::RequiresSetup, ErrorKind::RequiresSetup)
        );
        if !consistent {
            return Err(ContractError::inconsistent_outcome());
        }
        Ok(Self::base(
            product,
            operation,
            outcome,
            false,
            ExitCategory::Blocked,
            Some(error_kind),
        ))
    }

    pub fn failed(
        product: ProductId,
        operation: CommonOperation,
        outcome: OperationOutcome,
        category: ExitCategory,
        error_kind: ErrorKind,
    ) -> Result<Self, ContractError> {
        let consistent = match category {
            ExitCategory::OperationalFailure => {
                outcome == OperationOutcome::Failed
                    && matches!(error_kind, ErrorKind::Operational | ErrorKind::Network)
            }
            ExitCategory::InvalidInput => {
                outcome == OperationOutcome::Failed
                    && matches!(
                        error_kind,
                        ErrorKind::InvalidInvocation | ErrorKind::InvalidConfiguration
                    )
            }
            ExitCategory::AuthorityViolation => matches!(
                (outcome, error_kind),
                (
                    OperationOutcome::AuthenticityViolation,
                    ErrorKind::Authenticity
                ) | (OperationOutcome::IntegrityViolation, ErrorKind::Integrity)
                    | (OperationOutcome::AuthorityViolation, ErrorKind::Authority)
            ),
            ExitCategory::Completed | ExitCategory::Blocked | ExitCategory::Interrupted => {
                return Err(ContractError::inconsistent_category());
            }
        };
        if !consistent {
            return Err(ContractError::inconsistent_outcome());
        }
        Ok(Self::base(
            product,
            operation,
            outcome,
            false,
            category,
            Some(error_kind),
        ))
    }

    pub fn interrupted(product: ProductId, operation: CommonOperation) -> Self {
        Self::base(
            product,
            operation,
            OperationOutcome::Interrupted,
            false,
            ExitCategory::Interrupted,
            Some(ErrorKind::Interrupted),
        )
    }

    pub fn with_versions(
        mut self,
        installed_version: Option<&str>,
        available_version: Option<&str>,
    ) -> Self {
        self.installed_version = installed_version.map(str::to_owned);
        self.available_version = available_version.map(str::to_owned);
        self
    }

    pub fn with_cache_freshness(mut self, cache_freshness: CacheFreshness) -> Self {
        self.cache_freshness = Some(cache_freshness);
        self
    }

    pub fn with_installation_state(mut self, installation_state: InstallationState) -> Self {
        self.installation_state = Some(installation_state);
        self
    }

    fn base(
        product: ProductId,
        operation: CommonOperation,
        outcome: OperationOutcome,
        changed: bool,
        category: ExitCategory,
        error_kind: Option<ErrorKind>,
    ) -> Self {
        Self {
            schema: OPERATION_RESULT_SCHEMA,
            product,
            operation,
            outcome,
            changed,
            installed_version: None,
            available_version: None,
            cache_freshness: None,
            installation_state: None,
            exit_code: category.code(),
            error_kind,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Clean,
    Dirty,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    Debug,
    Release,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BuildInfo {
    pub schema: &'static str,
    pub product: ProductId,
    pub version: String,
    pub source_commit: String,
    pub source_state: SourceState,
    pub target: String,
    pub profile: BuildProfile,
    pub built_unix: u64,
}

impl BuildInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        product: ProductId,
        version: impl Into<String>,
        source_commit: impl Into<String>,
        source_state: SourceState,
        target: impl Into<String>,
        profile: BuildProfile,
        built_unix: u64,
    ) -> Result<Self, ContractError> {
        let version = version.into();
        let source_commit = source_commit.into();
        let target = target.into();
        for value in [&version, &source_commit, &target] {
            if !valid_identity_field(value) {
                return Err(ContractError::invalid_build_info());
            }
        }
        Ok(Self {
            schema: BUILD_INFO_SCHEMA,
            product,
            version,
            source_commit,
            source_state,
            target,
            profile,
            built_unix,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_build_values(
        product: ProductId,
        version: &str,
        source_commit: Option<&str>,
        source_dirty: Option<&str>,
        target: Option<&str>,
        profile: Option<&str>,
        built_unix: Option<&str>,
    ) -> Result<Self, ContractError> {
        let source_state = match source_dirty {
            Some("0") => SourceState::Clean,
            Some("1") => SourceState::Dirty,
            _ => SourceState::Unknown,
        };
        let profile = match profile {
            Some("debug") => BuildProfile::Debug,
            Some("release") => BuildProfile::Release,
            _ => BuildProfile::Unknown,
        };
        let built_unix = built_unix
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        Self::new(
            product,
            version,
            source_commit.unwrap_or("unknown"),
            source_state,
            target.unwrap_or("unknown"),
            profile,
            built_unix,
        )
    }
}

fn valid_identity_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_FIELD_LENGTH
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContractErrorKind {
    InvalidProductId,
    InvalidBuildInfo,
    InconsistentCategory,
    InconsistentOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractError {
    kind: ContractErrorKind,
}

impl ContractError {
    const fn invalid_product_id() -> Self {
        Self {
            kind: ContractErrorKind::InvalidProductId,
        }
    }

    const fn invalid_build_info() -> Self {
        Self {
            kind: ContractErrorKind::InvalidBuildInfo,
        }
    }

    const fn inconsistent_category() -> Self {
        Self {
            kind: ContractErrorKind::InconsistentCategory,
        }
    }

    const fn inconsistent_outcome() -> Self {
        Self {
            kind: ContractErrorKind::InconsistentOutcome,
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ContractErrorKind::InvalidProductId => "product id is invalid",
            ContractErrorKind::InvalidBuildInfo => "build information field is invalid",
            ContractErrorKind::InconsistentCategory => "operation result category is inconsistent",
            ContractErrorKind::InconsistentOutcome => "operation result outcome is inconsistent",
        })
    }
}

impl Error for ContractError {}
