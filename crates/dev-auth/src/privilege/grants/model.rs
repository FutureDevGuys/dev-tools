use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::time::Duration;

pub const RESULT_SCHEMA: &str = "dev-auth-administrator-grant-result-v1";
pub(super) const WIRE_SCHEMA: &str = "dev-auth-administrator-grant-control-v1";
pub(super) const FRAME_LIMIT: usize = 60 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantScope {
    User,
    Workload,
    /// The process tree of one program that `privilege run` starts in a
    /// boundary the coordinator owns (ADR 0139).
    Command,
}

impl GrantScope {
    /// Whether `request` and `delegate` can ask for this scope. Only `run`
    /// creates the boundary of a command scope.
    pub const fn requestable(self) -> bool {
        matches!(self, Self::User | Self::Workload)
    }

    /// Whether an observed logout ends grants of this scope (ADR 0136).
    pub const fn ends_at_logout(self) -> bool {
        matches!(self, Self::User | Self::Command)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Authority {
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    Administrator,
    ExactPlan {
        sha256: String,
    },
    Typed {
        operations: Vec<String>,
    },
}

impl Authority {
    pub fn validate(&self) -> Result<(), Failure> {
        match self {
            Self::Administrator => Ok(()),
            Self::ExactPlan { sha256 }
                if sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                Ok(())
            }
            Self::Typed { operations }
                if !operations.is_empty()
                    && operations.len() <= 64
                    && operations.iter().all(|operation| valid_name(operation))
                    && operations
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == operations.len() =>
            {
                Ok(())
            }
            _ => Err(Failure::InvalidRequest),
        }
    }

    pub fn permits(&self, narrower: &Self) -> bool {
        match (self, narrower) {
            (Self::Administrator, _) => true,
            (Self::ExactPlan { sha256: parent }, Self::ExactPlan { sha256: child }) => {
                parent == child
            }
            (Self::Typed { operations: parent }, Self::Typed { operations: child }) => {
                child.iter().all(|operation| parent.contains(operation))
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub scope: GrantScope,
    pub authority: Authority,
    pub duration_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<u64>,
}

impl GrantRequest {
    /// The grant one `run` request asks for: no requested idle cutoff or use
    /// budget, although the subject's policy may still impose them.
    pub fn command(authority: Authority, duration_seconds: u64) -> Self {
        Self {
            scope: GrantScope::Command,
            authority,
            duration_seconds,
            idle_seconds: None,
            uses: None,
        }
    }

    pub fn validate(&self) -> Result<(), Failure> {
        self.authority.validate()?;
        #[cfg(target_os = "linux")]
        if Duration::from_secs(self.duration_seconds)
            > dev_tools_privilege_session::linux::MAX_BOOT_DEADLINE
        {
            return Err(Failure::InvalidRequest);
        }
        if self.duration_seconds == 0
            || self.duration_seconds.checked_mul(1_000).is_none()
            || self
                .idle_seconds
                .is_some_and(|idle| idle == 0 || idle > self.duration_seconds)
            || self.uses == Some(0)
        {
            return Err(Failure::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    #[serde(with = "super::native_text")]
    pub program: OsString,
    #[serde(with = "super::native_text::sequence")]
    pub arguments: Vec<OsString>,
    #[serde(with = "super::native_text")]
    pub working_directory: OsString,
    #[serde(with = "super::native_text::environment")]
    pub environment: Vec<(OsString, OsString)>,
    pub terminal: bool,
}

/// A remaining-time check on the grant that covers a status caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequirement {
    pub remaining_seconds: u64,
    /// Check the caller's routable grant of this scope instead of the one
    /// sudo routing selects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GrantScope>,
}

impl GrantRequirement {
    pub fn validate(&self) -> Result<(), Failure> {
        if self.remaining_seconds == 0 || self.remaining_seconds.checked_mul(1_000).is_none() {
            return Err(Failure::InvalidRequest);
        }
        Ok(())
    }

    /// Whether a covering grant is active with at least the required time
    /// left before its hard deadline.
    pub fn met_by(&self, grant: &Grant) -> bool {
        grant.state == GrantState::Active
            && grant.remaining_milliseconds >= self.remaining_seconds.saturating_mul(1_000)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlRequest {
    Request {
        request: GrantRequest,
    },
    /// One freshly approved command-scoped grant for the program it starts as
    /// the caller. The program's open descriptor travels beside the request;
    /// `executable` is its canonical path, which the coordinator verifies.
    Run {
        authority: Authority,
        duration_seconds: u64,
        #[serde(with = "super::native_text")]
        executable: OsString,
        execution: Execution,
    },
    #[doc(hidden)]
    LaunchRequest {
        request: GrantRequest,
    },
    #[doc(hidden)]
    ActivateLaunch {
        grant: String,
        #[serde(default)]
        bootstrap: bool,
    },
    #[doc(hidden)]
    CommitLaunch {
        grant: String,
    },
    Status {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requirement: Option<GrantRequirement>,
    },
    Inspect {
        grant: String,
    },
    Exec {
        grant: Option<String>,
        execution: Execution,
    },
    RunPlan {
        grant: Option<String>,
        authority: Authority,
        terminal: bool,
    },
    #[doc(hidden)]
    SudoRelay {
        grant: String,
        execution: Execution,
    },
    Delegate {
        grant: String,
        request: GrantRequest,
    },
    Revoke {
        grant: String,
    },
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    Leave,
}

impl ControlRequest {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Request { .. } | Self::LaunchRequest { .. } => "request",
            Self::ActivateLaunch { .. } => "activate_launch",
            Self::CommitLaunch { .. } => "commit_launch",
            Self::Run { .. } => "run",
            Self::Status { .. } => "status",
            Self::Inspect { .. } => "inspect",
            Self::Exec { .. } | Self::SudoRelay { .. } | Self::RunPlan { .. } => "exec",
            Self::Delegate { .. } => "delegate",
            Self::Revoke { .. } => "revoke",
            Self::Leave => "leave",
        }
    }

    pub fn is_observation(&self) -> bool {
        matches!(self, Self::Status { .. } | Self::Inspect { .. })
    }

    pub fn validate(&self) -> Result<(), Failure> {
        match self {
            Self::Request { request } | Self::LaunchRequest { request } => {
                requestable(request)?;
                request.validate()
            }
            Self::Run {
                authority,
                duration_seconds,
                executable,
                execution,
            } => {
                if *authority != Authority::Administrator
                    || !std::path::Path::new(executable).is_absolute()
                    || executable.as_encoded_bytes().contains(&0)
                {
                    return Err(Failure::InvalidRequest);
                }
                GrantRequest::command(authority.clone(), *duration_seconds).validate()?;
                validate_execution(execution)
            }
            Self::ActivateLaunch { grant, .. } | Self::CommitLaunch { grant } => validate_id(grant),
            Self::Inspect { grant } | Self::Revoke { grant } => validate_id(grant),
            Self::Delegate { grant, request } => {
                validate_id(grant)?;
                requestable(request)?;
                request.validate()
            }
            Self::RunPlan {
                grant, authority, ..
            } => {
                if let Some(grant) = grant {
                    validate_id(grant)?;
                }
                authority.validate()?;
                match authority {
                    Authority::ExactPlan { .. } => Ok(()),
                    Authority::Typed { operations } if operations.len() == 1 => Ok(()),
                    _ => Err(Failure::InvalidRequest),
                }
            }
            Self::Exec { grant, execution } => {
                if let Some(grant) = grant {
                    validate_id(grant)?;
                }
                validate_execution(execution)
            }
            Self::SudoRelay { grant, execution } => {
                validate_id(grant)?;
                validate_execution(execution)
            }
            Self::Status { requirement } => requirement
                .as_ref()
                .map_or(Ok(()), GrantRequirement::validate),
            Self::Leave => Ok(()),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn execution_terminal(&self) -> Option<bool> {
        match self {
            Self::Exec { execution, .. }
            | Self::SudoRelay { execution, .. }
            | Self::Run { execution, .. } => Some(execution.terminal),
            Self::RunPlan { terminal, .. } => Some(*terminal),
            _ => None,
        }
    }
}

/// `request` and `delegate` cannot ask for a command scope, because only
/// `run` creates the boundary that scope names (ADR 0139).
fn requestable(request: &GrantRequest) -> Result<(), Failure> {
    if request.scope.requestable() {
        Ok(())
    } else {
        Err(Failure::InvalidRequest)
    }
}

fn validate_execution(execution: &Execution) -> Result<(), Failure> {
    if execution.program.is_empty()
        || !std::path::Path::new(&execution.working_directory).is_absolute()
        || execution.arguments.len() > 1024
        || execution.environment.len() > 1024
    {
        return Err(Failure::InvalidRequest);
    }
    validate_native_command(
        &execution.program,
        &execution.arguments,
        &execution.working_directory,
        &execution.environment,
    )
}

pub(super) fn validate_native_command(
    program: &std::ffi::OsStr,
    arguments: &[OsString],
    directory: &std::ffi::OsStr,
    environment: &[(OsString, OsString)],
) -> Result<(), Failure> {
    let has_nul = |value: &std::ffi::OsStr| value.as_encoded_bytes().contains(&0);
    let mut names = std::collections::BTreeSet::new();
    if has_nul(program)
        || has_nul(directory)
        || arguments.iter().any(|value| has_nul(value))
        || environment.iter().any(|(name, value)| {
            name.is_empty()
                || has_nul(name)
                || has_nul(value)
                || name.as_encoded_bytes().contains(&b'=')
                || !names.insert(name)
        })
    {
        return Err(Failure::InvalidRequest);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Pending,
    Active,
    Stopping,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub scope: GrantScope,
    pub authority: Authority,
    pub state: GrantState,
    pub duration_seconds: u64,
    pub remaining_milliseconds: u64,
    pub idle_seconds: Option<u64>,
    pub remaining_uses: Option<u64>,
    pub stop_reason: Option<String>,
    pub cleanup_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    InvalidRequest,
    RequiresSetup,
    ApprovalRequired,
    ApprovalDenied,
    AuthorityDenied,
    NoGrant,
    GrantExpired,
    GrantRevoked,
    NativeUnavailable,
    Busy,
    CleanupFailed,
    ProtocolViolation,
    RuntimeFailure,
    OutputLimit,
    /// The covering grant ends before a status requirement's remaining time.
    InsufficientRemaining,
    Interrupted,
}

impl Failure {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidRequest => 2,
            Self::RequiresSetup
            | Self::ApprovalRequired
            | Self::NoGrant
            | Self::NativeUnavailable
            | Self::Busy
            | Self::InsufficientRemaining => 3,
            Self::ApprovalDenied
            | Self::AuthorityDenied
            | Self::GrantExpired
            | Self::GrantRevoked
            | Self::ProtocolViolation => 4,
            Self::CleanupFailed | Self::RuntimeFailure | Self::OutputLimit => 1,
            Self::Interrupted => 130,
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid administrator grant request",
            Self::RequiresSetup => "administrator service requires product setup",
            Self::ApprovalRequired => "a new administrator grant requires visible native approval",
            Self::ApprovalDenied => "native administrator approval was denied",
            Self::AuthorityDenied => {
                "native identity or administrator policy denied this operation"
            }
            Self::NoGrant => "no eligible administrator grant is selected",
            Self::GrantExpired => "the administrator grant has expired",
            Self::GrantRevoked => "the administrator grant has been revoked",
            Self::NativeUnavailable => "the required native administrator boundary is unavailable",
            Self::Busy => "the administrator service is at its bounded request capacity",
            Self::CleanupFailed => "privileged process cleanup is incomplete",
            Self::ProtocolViolation => "administrator service authentication or framing failed",
            Self::RuntimeFailure => {
                "administrator operation failed; entered mutation may be incomplete"
            }
            Self::OutputLimit => "approved command graph exceeded its external output budget",
            Self::InsufficientRemaining => {
                "the covering administrator grant ends before the required remaining time"
            }
            Self::Interrupted => "administrator operation was interrupted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub schema: String,
    pub operation: String,
    pub changed: Option<bool>,
    pub error_kind: Option<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputObservation>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OutputCounts {
    pub stdout: u64,
    pub stderr: u64,
    /// PTY output is merged and counted once, alongside separately redirected
    /// stdout/stderr. Graph-internal pipes and terminal input are excluded.
    pub merged_pty: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputObservation {
    pub limit_bytes: u64,
    /// Bounded observation including at most one overflow detector byte. Exact
    /// after complete=true; otherwise pointwise confirmed lower bounds.
    pub observed: OutputCounts,
    /// Exact after complete=true; otherwise a confirmed lower bound because a
    /// killed writer may have completed a native write before publishing it.
    pub forwarded: OutputCounts,
    /// Every owned output stream reached EOF and every sink writer joined.
    pub complete: bool,
    pub limit_exceeded: bool,
}

impl ControlResult {
    pub fn success(operation: &str, changed: bool) -> Self {
        Self {
            schema: RESULT_SCHEMA.to_owned(),
            operation: operation.to_owned(),
            changed: Some(changed),
            error_kind: None,
            grant: None,
            grants: Vec::new(),
            child_exit_code: None,
            child_signal: None,
            output: None,
        }
    }

    pub fn failure(operation: &str, failure: Failure, changed: Option<bool>) -> Self {
        let mut result = Self::success(operation, false);
        result.error_kind = Some(failure);
        result.changed = changed;
        result
    }

    pub fn exit_code(&self) -> i32 {
        self.error_kind.map(Failure::exit_code).unwrap_or_else(|| {
            self.child_exit_code
                .or_else(|| self.child_signal.map(|signal| 128 + signal))
                .unwrap_or(0)
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub schema: String,
    pub request: ControlRequest,
}

pub fn parse_duration(value: &str) -> Result<Duration, Failure> {
    let (number, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1_u64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3600),
        Some(b'd') => (&value[..value.len() - 1], 86400),
        _ => return Err(Failure::InvalidRequest),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::InvalidRequest);
    }
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .filter(|value| *value > 0 && value.checked_mul(1000).is_some())
        .ok_or(Failure::InvalidRequest)?;
    Ok(Duration::from_secs(seconds))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}

fn validate_id(value: &str) -> Result<(), Failure> {
    if value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Failure::InvalidRequest)
    }
}
