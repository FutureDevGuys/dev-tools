use super::{native_text, Authority, Failure, GrantRequest, GrantScope};
use dev_tools_privilege_session::{Constraint, LeaseLimits};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::time::Duration;

pub const POLICY_SCHEMA: &str = "dev-auth-privilege-policy-v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Account {
    Unix { uid: u32 },
    Windows { sid: String },
}

impl Account {
    pub fn validate(&self) -> Result<(), Failure> {
        match self {
            Self::Unix { uid } if *uid != 0 => Ok(()),
            Self::Windows { sid }
                if sid.starts_with("S-1-")
                    && sid.len() <= 184
                    && sid[4..].split('-').all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                    }) =>
            {
                Ok(())
            }
            _ => Err(Failure::InvalidRequest),
        }
    }
}

/// Native observations only. Workload keys identify retained OS objects, not
/// task names, environment variables, submitted PIDs or serialized grant IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(target_os = "linux")]
pub(super) struct NativeScope {
    pub account: Account,
    pub workload: Option<u128>,
}

#[cfg(target_os = "linux")]
impl Constraint for NativeScope {
    fn contains(&self, narrower: &Self) -> bool {
        self.account == narrower.account
            && (self.workload.is_none() || self.workload == narrower.workload)
    }
}

impl Constraint for Authority {
    fn contains(&self, narrower: &Self) -> bool {
        self.permits(narrower)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub subjects: Vec<SubjectPolicy>,
    #[serde(with = "native_text")]
    pub sudo_program: OsString,
    #[serde(default)]
    pub plans: BTreeMap<String, ExecutionPlan>,
    #[serde(default)]
    pub operations: BTreeMap<String, ExecutionPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectPolicy {
    pub account: Account,
    pub scopes: Vec<GrantScope>,
    pub authorities: Vec<Authority>,
    pub maximum_duration_seconds: u64,
    #[serde(default)]
    pub idle_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub maximum_uses: Option<u64>,
    #[serde(default)]
    pub allow_delegation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    pub nodes: Vec<PlanCommand>,
    #[serde(default)]
    pub pipes: Vec<PlanPipe>,
    pub exit_policy: ExitPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCommand {
    #[serde(with = "native_text")]
    pub program: OsString,
    #[serde(with = "native_text::sequence")]
    pub arguments: Vec<OsString>,
    #[serde(with = "native_text")]
    pub working_directory: OsString,
    #[serde(default, with = "native_text::environment")]
    pub environment: Vec<(OsString, OsString)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPipe {
    pub from: usize,
    pub to: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitPolicy {
    Last,
    All,
    Pipefail,
}

impl Policy {
    /// A non-authorizing template: no account has administrator permission.
    pub fn template() -> Self {
        Self {
            schema: POLICY_SCHEMA.to_owned(),
            subjects: Vec::new(),
            sudo_program: OsString::from("/usr/bin/sudo"),
            plans: BTreeMap::new(),
            operations: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<(), Failure> {
        if self.schema != POLICY_SCHEMA
            || self.subjects.len() > 128
            || !std::path::Path::new(&self.sudo_program).is_absolute()
            || self.plans.len() > 128
            || self.operations.len() > 128
        {
            return Err(Failure::InvalidRequest);
        }
        let mut accounts = std::collections::BTreeSet::new();
        for subject in &self.subjects {
            subject.account.validate()?;
            if !accounts.insert(&subject.account)
                || subject.scopes.is_empty()
                || subject.scopes.len() > 2
                || (subject.scopes.len() == 2 && subject.scopes[0] == subject.scopes[1])
                || subject.authorities.is_empty()
                || subject.authorities.len() > 128
            {
                return Err(Failure::InvalidRequest);
            }
            GrantRequest {
                scope: subject.scopes[0],
                authority: Authority::Administrator,
                duration_seconds: subject.maximum_duration_seconds,
                idle_seconds: subject.idle_timeout_seconds,
                uses: subject.maximum_uses,
            }
            .validate()?;
            for authority in &subject.authorities {
                authority.validate()?;
                match authority {
                    Authority::ExactPlan { sha256 } if !self.plans.contains_key(sha256) => {
                        return Err(Failure::InvalidRequest)
                    }
                    Authority::Typed { operations }
                        if operations
                            .iter()
                            .any(|name| !self.operations.contains_key(name)) =>
                    {
                        return Err(Failure::InvalidRequest)
                    }
                    _ => {}
                }
            }
        }
        for (digest, plan) in &self.plans {
            plan.validate()?;
            if &plan.digest()? != digest {
                return Err(Failure::InvalidRequest);
            }
        }
        for (name, plan) in &self.operations {
            Authority::Typed {
                operations: vec![name.clone()],
            }
            .validate()?;
            plan.validate()?;
        }
        Ok(())
    }

    pub fn subject(&self, account: &Account) -> Result<&SubjectPolicy, Failure> {
        self.subjects
            .iter()
            .find(|subject| &subject.account == account)
            .ok_or(Failure::AuthorityDenied)
    }

    pub fn approve_limits(
        &self,
        account: &Account,
        request: &GrantRequest,
    ) -> Result<LeaseLimits, Failure> {
        request.validate()?;
        let subject = self.subject(account)?;
        match &request.authority {
            Authority::ExactPlan { sha256 } if !self.plans.contains_key(sha256) => {
                return Err(Failure::AuthorityDenied)
            }
            Authority::Typed { operations }
                if operations
                    .iter()
                    .any(|name| !self.operations.contains_key(name)) =>
            {
                return Err(Failure::AuthorityDenied)
            }
            _ => {}
        }
        if !subject.scopes.contains(&request.scope)
            || !subject
                .authorities
                .iter()
                .any(|authority| authority.permits(&request.authority))
            || request.duration_seconds > subject.maximum_duration_seconds
            || subject
                .maximum_uses
                .is_some_and(|maximum| request.uses.is_none_or(|uses| uses > maximum))
        {
            return Err(Failure::AuthorityDenied);
        }
        if let Some(idle) = subject.idle_timeout_seconds {
            if request
                .idle_seconds
                .is_some_and(|requested| requested > idle)
            {
                return Err(Failure::AuthorityDenied);
            }
        }
        let idle = match (subject.idle_timeout_seconds, request.idle_seconds) {
            (Some(policy), Some(request)) => policy.min(request),
            (Some(policy), None) => policy,
            (None, Some(request)) => request,
            (None, None) => request.duration_seconds,
        }
        .min(request.duration_seconds);
        let policy = LeaseLimits::from_administrator_policy(
            Duration::from_secs(idle),
            Duration::from_secs(subject.maximum_duration_seconds),
        )
        .map_err(|_| Failure::InvalidRequest)?;
        LeaseLimits::for_approved_duration(policy, Duration::from_secs(request.duration_seconds))
            .map_err(|_| Failure::AuthorityDenied)
    }
}

impl ExecutionPlan {
    pub fn validate(&self) -> Result<(), Failure> {
        if self.nodes.is_empty() || self.nodes.len() > 64 || self.pipes.len() > 63 {
            return Err(Failure::InvalidRequest);
        }
        for node in &self.nodes {
            if !std::path::Path::new(&node.program).is_absolute()
                || !std::path::Path::new(&node.working_directory).is_absolute()
                || node.arguments.len() > 1024
                || node.environment.len() > 128
            {
                return Err(Failure::InvalidRequest);
            }
            super::model::validate_native_command(
                &node.program,
                &node.arguments,
                &node.working_directory,
                &node.environment,
            )?;
        }
        let mut incoming = vec![false; self.nodes.len()];
        let mut outgoing = vec![false; self.nodes.len()];
        for pipe in &self.pipes {
            // Nodes are a topological order; one stdin/stdout can participate in
            // at most one binary pipe. Independent roots form an executable DAG.
            if pipe.from >= pipe.to
                || pipe.to >= self.nodes.len()
                || incoming[pipe.to]
                || outgoing[pipe.from]
            {
                return Err(Failure::InvalidRequest);
            }
            incoming[pipe.to] = true;
            outgoing[pipe.from] = true;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, Failure> {
        use sha2::{Digest, Sha256};
        let bytes = serde_jcs::to_vec(self).map_err(|_| Failure::InvalidRequest)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}
